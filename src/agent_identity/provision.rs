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

fn history_custody_for_policy(
    authority: &AccountId,
    summary: &arkret_sdk::RecoveryPolicySummary,
) -> anyhow::Result<arkret_models_crypto::AgentHistoryCustody> {
    summary.validate_shape()?;
    let policy = summary.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Agent history custody requires the accepted recovery policy")
    })?;
    policy.validate_shape()?;
    let now = crate::clock::now_utc();
    anyhow::ensure!(
        summary.account_id == *authority
            && policy.account_id == *authority
            && policy.policy_id == summary.policy_id
            && policy.version == summary.version
            && policy.not_before.is_none_or(|start| start <= now)
            && policy.expires_at.is_none_or(|end| now < end),
        "Agent history custody policy differs from the current controller Account"
    );
    let mut recipients = policy
        .methods
        .iter()
        .filter_map(|method| match method {
            arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .filter(|key| {
            key.signature_algorithm == arkret_sdk::RecoverySignatureAlgorithm::Ed25519
                && key.not_before <= now
                && now < key.expires_at
                && key.revoked_at.is_none_or(|end| now < end)
                && key.backup_hpke.not_before <= now
                && now < key.backup_hpke.expires_at
                && key.backup_hpke.revoked_at.is_none_or(|end| now < end)
                && key
                    .backup_hpke
                    .hpke_suites
                    .contains(&arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
        });
    let recipient = recipients.next().ok_or_else(|| {
        anyhow::anyhow!("Agent history custody requires an active controller backup-HPKE recipient")
    })?;
    anyhow::ensure!(
        recipients.next().is_none(),
        "Agent history custody requires an unambiguous controller backup-HPKE recipient"
    );
    Ok(arkret_models_crypto::AgentHistoryCustody {
        custodian_actor_id: arkret_sdk::ActorId::account(authority.clone()),
        recovery_policy_ref: arkret_sdk::RecoveryPolicyRef {
            policy_id: summary.policy_id.clone(),
            policy_version: summary.version,
        },
        recipient_key_ref: recipient.backup_hpke.key_agreement_ref.clone(),
    })
}

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
    pub(crate) avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    pub(crate) requested_scope: AgentKeyScope,
    pub(crate) inception: PreparedPrincipalInception,
    pub(crate) keys: AgentDidKeys,
    pub(crate) preparation: Option<AgentProvisionAwaitingControllerEvent>,
    pub(crate) authored: Option<AuthoredProvision>,
    pub(crate) binding_operation: Option<DidOperationSubmitRequestBody>,
    pub(crate) outcome: Option<AgentProvisionComplete>,
    pub(crate) profile_event: Option<arkret_sdk::AuthoredEvent>,
    pub(crate) profile_commit: Option<arkret_sdk::RealmCommit>,
}

impl ProvisionCeremony {
    pub(crate) fn is_complete(&self) -> bool {
        self.outcome.is_some() && (self.avatar_blob_ref.is_none() || self.profile_commit.is_some())
    }

    pub(crate) fn profile_intent(&self) -> anyhow::Result<arkret_sdk::EventIntent> {
        let outcome = self
            .outcome
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent provision is not accepted"))?;
        let avatar = self
            .avatar_blob_ref
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Agent intent has no avatar"))?;
        let agent = AccountId::new(outcome.agent_id.clone(), self.authority.station_id.clone());
        Ok(
            arkret_event_draft::TypedEventDraft::<arkret_sdk::event_spec::ProfileCreate>::new(
                arkret_sdk::ScopeRef::Realm {
                    realm_id: outcome.principal_control_realm_id.clone(),
                },
                arkret_sdk::ActorId::account(agent),
                arkret_models_collaboration::events_payloads::ActorProfileCreatePayload {
                    object: arkret_sdk::ActorProfileDefinition {
                        principal_id: Some(outcome.agent_id.clone()),
                        actor_id: None,
                        actor_kind: arkret_sdk::ActorKind::Agent,
                        display_name: self.slug.clone(),
                        handle: None,
                        agent_slug: Some(self.slug.clone()),
                        avatar_blob_ref: Some(avatar),
                        accountable_principal_ids: Some(vec![self.authority.principal_id.clone()]),
                        profile_fields: Default::default(),
                        encrypted_private_fields: None,
                    },
                },
            )?
            .with_executed_by(arkret_sdk::ActorId::account(self.authority.clone()))
            .with_authorization_ref(arkret_sdk::AuthorizationRef::from(
                outcome.controller_authorization_ref.clone(),
            ))
            .into_intent(crate::clock::now_utc())?,
        )
    }

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
        if let Some(profile) = &self.profile_event {
            let intent = self.profile_intent()?;
            let event = profile.event();
            anyhow::ensure!(
                event.kind == *intent.kind()
                    && &event.scope_ref == intent.scope_ref()
                    && &event.actor_id == intent.actor_id()
                    && event.executed_by.as_ref() == intent.executed_by()
                    && event.authorization_ref.as_ref() == intent.authorization_ref()
                    && crate::canonical::canonical_json_bytes(&event.payload)?
                        == crate::canonical::canonical_json_bytes(intent.payload())?
                    && event.producer_proof.is_some(),
                "Agent profile substituted its frozen avatar, Account, PCR or controller delegation"
            );
        }
        if let Some(commit) = &self.profile_commit {
            let event = self
                .profile_event
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Agent profile commit lost its signed original"))?;
            anyhow::ensure!(
                commit.event_ref == event.event_id && commit.realm_id == event.realm_id,
                "Agent profile result does not cover its exact signed original"
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
                    &record.avatar_blob_ref,
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
        preserve!(profile_event);
        preserve!(profile_commit);
        Ok(())
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    #[test]
    fn custody_selects_exact_controller_policy_and_refuses_foreign_revoked_or_ambiguous_keys() {
        let did = arkret_sdk::Did::new("did:web:controller.example").unwrap();
        let account = crate::test_support::authority(did.as_str());
        let device = DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap();
        let signer = std::sync::Arc::new(
            crate::event_signer::build_ed25519_signer_with_verification_method(
                [47; 32],
                did.as_str(),
                format!("{did}#{device}"),
            ),
        );
        let _guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
        let material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            &crate::recovery_crypto::format_recovery_key(&[7; 32]),
            "",
            0,
        )
        .unwrap();
        let policy: arkret_sdk::RecoveryPolicy = serde_json::from_value(
            crate::recovery_flow::build_signed_genesis_recovery_policy_for_session_device(
                &did,
                &account,
                "ak:trust_domain:controller.example",
                &device,
                &material,
            )
            .unwrap(),
        )
        .unwrap();
        // This exercises recipient selection. The production authenticated
        // resource supplies native policy acceptance; this summary is a fixture.
        let summary = arkret_sdk::RecoveryPolicySummary {
            policy_id: policy.policy_id.clone(),
            account_id: account.clone(),
            version: policy.version,
            acceptance_basis_ref: arkret_sdk::RealmCommitId::from_digest([48; 32]),
            recovery_policy_ref: Some(arkret_sdk::RecoveryPolicyRef {
                policy_id: policy.policy_id.clone(),
                policy_version: policy.version,
            }),
            trust_domain: policy.trust_domain.clone(),
            supersedes_id: None,
            issued_at: policy.issued_at,
            expires_at: None,
            accepted_at: Some(policy.issued_at),
            methods: policy.methods.clone(),
            policy: Some(policy),
        };
        let custody = history_custody_for_policy(&account, &summary).unwrap();
        assert_eq!(
            custody.custodian_actor_id,
            arkret_sdk::ActorId::account(account.clone())
        );
        assert_eq!(
            custody.recovery_policy_ref,
            summary.recovery_policy_ref.clone().unwrap()
        );
        let arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } = &summary.methods[0] else {
            unreachable!()
        };
        assert_eq!(
            custody.recipient_key_ref,
            keys[0].backup_hpke.key_agreement_ref
        );

        let mut foreign = account.clone();
        foreign.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:another-station.example").unwrap();
        assert!(history_custody_for_policy(&foreign, &summary).is_err());
        let mut missing = summary.clone();
        missing.policy = None;
        assert!(history_custody_for_policy(&account, &missing).is_err());
        let mut revoked = summary.clone();
        let body = revoked.policy.as_mut().unwrap();
        let arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } = &mut body.methods[0] else {
            unreachable!()
        };
        keys[0].backup_hpke.revoked_at = Some(body.issued_at);
        revoked.methods = body.methods.clone();
        assert!(
            history_custody_for_policy(&account, &revoked)
                .unwrap_err()
                .to_string()
                .contains("active controller")
        );
        let mut ambiguous = summary.clone();
        let body = ambiguous.policy.as_mut().unwrap();
        let arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } = &mut body.methods[0] else {
            unreachable!()
        };
        let mut other = keys[0].clone();
        other.verification_method =
            arkret_sdk::DidUrl::new(format!("{did}#another-recovery-proof")).unwrap();
        other.backup_hpke.key_agreement_ref =
            arkret_sdk::DidUrl::new(format!("{did}#another-backup-hpke")).unwrap();
        keys.push(other);
        ambiguous.methods = body.methods.clone();
        assert!(
            history_custody_for_policy(&account, &ambiguous)
                .unwrap_err()
                .to_string()
                .contains("unambiguous")
        );
    }
}
