//! Principal inception and recovery-handoff durable checkpoints.
//!
//! Secret material is deliberately absent from every serializable type in this
//! module. Callers hold the mnemonic only in a short-lived UI/secure-custody
//! buffer, derive public artifacts through the SDK, then persist this public
//! draft. A restart resumes by asking the user to present the same recovery
//! secret and re-deriving the public commitments.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrincipalAuthorityModel {
    CrossSigning,
    EnrollmentAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InceptionOperationIds {
    pub(crate) did_operation: String,
    pub(crate) pcr_bootstrap: String,
    pub(crate) recovery_policy: String,
    pub(crate) first_recovery_backup: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CustodyConfirmation {
    WordsReentered {
        confirmed_at: DateTime<Utc>,
    },
    HardwareAcknowledged {
        acknowledgement_digest: String,
        confirmed_at: DateTime<Utc>,
    },
    GuardianAcknowledged {
        acknowledgement_digest: String,
        confirmed_at: DateTime<Utc>,
    },
    PersonalNodeDevicePersisted {
        persistence_receipt_digest: String,
        confirmed_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InceptionCheckpoint {
    Prepared,
    CustodyConfirmed {
        confirmation: CustodyConfirmation,
    },
    InceptionAccepted {
        operation_ref: String,
        accepted_head_digest: String,
    },
    BootstrapAccepted {
        receipt_id: String,
        create_event_id: String,
        authorize_event_id: String,
    },
    RecoveryMaterialAccepted {
        recovery_policy_ref: arkret_sdk::RecoveryPolicyRef,
        did_recovery_backup_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicPrincipalInceptionDraft {
    pub(crate) draft_id: String,
    pub(crate) authority_model: PrincipalAuthorityModel,
    pub(crate) did: String,
    pub(crate) local_id: String,
    pub(crate) version_id: String,
    pub(crate) root_public_key_multibase: String,
    pub(crate) next_root_public_key_multibase: String,
    pub(crate) next_root_key_hash: String,
    pub(crate) recovery_proof_public_key_multibase: String,
    pub(crate) backup_hpke_public_key_multibase: String,
    pub(crate) root_verification_method: String,
    pub(crate) document_url: String,
    pub(crate) log_url: String,
    pub(crate) submit_body: serde_json::Value,
    pub(crate) idempotency: InceptionOperationIds,
    pub(crate) pcr_bootstrap_hlc: String,
    pub(crate) checkpoint: InceptionCheckpoint,
    pub(crate) prepared_at: DateTime<Utc>,
}

pub(crate) enum PrincipalEnrollmentInput<'a> {
    ExternalAuthority {
        authority_did: &'a str,
    },
    SelfAuthority {
        principal_signing_public_key_multibase: &'a str,
        enrollment_public_key_multibase: &'a str,
        principal_signing_fragment: Option<&'a str>,
        enrollment_fragment: Option<&'a str>,
    },
}

pub(crate) struct PreparePrincipalInception<'a> {
    pub(crate) principal_endpoint: &'a Url,
    pub(crate) local_id: &'a str,
    pub(crate) also_known_as: &'a [String],
    pub(crate) version_time: DateTime<Utc>,
    pub(crate) enrollment: PrincipalEnrollmentInput<'a>,
}

impl PublicPrincipalInceptionDraft {
    pub(crate) fn prepare_from_bip39(
        recovery_mnemonic: &str,
        passphrase: &str,
        input: PreparePrincipalInception<'_>,
    ) -> anyhow::Result<Self> {
        let keys = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_mnemonic,
            passphrase,
            0,
        )?;
        let (authority_model, enrollment) = match input.enrollment {
            PrincipalEnrollmentInput::ExternalAuthority { authority_did } => (
                PrincipalAuthorityModel::EnrollmentAuthority,
                arkret_sdk::webvh::PrincipalEnrollmentDelegation::ExternalAuthority {
                    authority_did,
                },
            ),
            PrincipalEnrollmentInput::SelfAuthority {
                principal_signing_public_key_multibase,
                enrollment_public_key_multibase,
                principal_signing_fragment,
                enrollment_fragment,
            } => (
                PrincipalAuthorityModel::CrossSigning,
                arkret_sdk::webvh::PrincipalEnrollmentDelegation::SelfAuthority {
                    principal_signing_public_key_multibase,
                    enrollment_public_key_multibase,
                    principal_signing_fragment,
                    enrollment_fragment,
                },
            ),
        };
        let prepared = arkret_sdk::webvh::prepare_principal_inception(
            &arkret_sdk::webvh::PrincipalInceptionInput {
                principal_endpoint: input.principal_endpoint,
                local_id: input.local_id,
                also_known_as: input.also_known_as,
                version_time: input.version_time,
                root_seed: &keys.root_seed,
                next_root_public_key_multibase: &keys.next_root_public_key_multikey,
                enrollment,
            },
        )?;
        let submit_body = serde_json::to_value(&prepared.submit_body)?;
        let draft_id = arkret_sdk::canonical::canonical_sha256(&serde_json::json!({
            "did": prepared.did,
            "version_id": prepared.version_id,
            "submit_body": submit_body,
        }))?;
        Ok(Self {
            draft_id,
            authority_model,
            did: prepared.did,
            local_id: prepared.local_id,
            version_id: prepared.version_id,
            root_public_key_multibase: prepared.root_public_key_multibase,
            next_root_public_key_multibase: prepared.next_root_public_key_multibase,
            next_root_key_hash: prepared.next_root_key_hash,
            recovery_proof_public_key_multibase: keys.recovery_proof_public_key_multikey.clone(),
            backup_hpke_public_key_multibase: keys.backup_hpke_public_key_multikey.clone(),
            root_verification_method: prepared.root_verification_method,
            document_url: prepared.document_url,
            log_url: prepared.log_url,
            submit_body,
            idempotency: InceptionOperationIds {
                did_operation: crate::operation::uuid_v7(),
                pcr_bootstrap: crate::operation::uuid_v7(),
                recovery_policy: crate::operation::uuid_v7(),
                first_recovery_backup: crate::operation::uuid_v7(),
            },
            pcr_bootstrap_hlc: crate::hlc::Hlc::now("identity-root-bootstrap").encode(),
            checkpoint: InceptionCheckpoint::Prepared,
            prepared_at: Utc::now(),
        })
    }

    pub(crate) fn confirm_words_reentered(
        &mut self,
        recovery_mnemonic: &str,
        confirmation: &str,
        passphrase: &str,
    ) -> anyhow::Result<()> {
        if !crate::recovery_crypto::recovery_key_confirmation_matches(
            recovery_mnemonic,
            confirmation,
        ) {
            anyhow::bail!("recovery mnemonic confirmation does not match");
        }
        self.ensure_recovery_secret_matches(recovery_mnemonic, passphrase)?;
        self.confirm_custody(CustodyConfirmation::WordsReentered {
            confirmed_at: Utc::now(),
        })
    }

    pub(crate) fn confirm_custody(
        &mut self,
        confirmation: CustodyConfirmation,
    ) -> anyhow::Result<()> {
        if !matches!(self.checkpoint, InceptionCheckpoint::Prepared) {
            anyhow::bail!("custody can only be confirmed for a prepared inception draft");
        }
        let digest = match &confirmation {
            CustodyConfirmation::HardwareAcknowledged {
                acknowledgement_digest,
                ..
            }
            | CustodyConfirmation::GuardianAcknowledged {
                acknowledgement_digest,
                ..
            } => Some(acknowledgement_digest),
            CustodyConfirmation::PersonalNodeDevicePersisted {
                persistence_receipt_digest,
                ..
            } => Some(persistence_receipt_digest),
            CustodyConfirmation::WordsReentered { .. } => None,
        };
        if digest.is_some_and(|digest| !valid_digest(digest)) {
            anyhow::bail!("custody acknowledgement must be a canonical sha256 digest");
        }
        self.checkpoint = InceptionCheckpoint::CustodyConfirmed { confirmation };
        Ok(())
    }

    pub(crate) fn ensure_recovery_secret_matches(
        &self,
        recovery_mnemonic: &str,
        passphrase: &str,
    ) -> anyhow::Result<()> {
        let keys = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_mnemonic,
            passphrase,
            0,
        )?;
        if keys.root_public_key_multikey != self.root_public_key_multibase
            || keys.next_root_public_key_multikey != self.next_root_public_key_multibase
            || keys.next_root_key_hash != self.next_root_key_hash
            || keys.recovery_proof_public_key_multikey != self.recovery_proof_public_key_multibase
            || keys.backup_hpke_public_key_multikey != self.backup_hpke_public_key_multibase
        {
            anyhow::bail!("recovery secret does not reproduce the persisted inception draft");
        }
        Ok(())
    }

    pub(crate) fn did_operation_submission(
        &self,
    ) -> anyhow::Result<arkret_sdk::DidOperationSubmitRequestBody> {
        if !matches!(
            self.checkpoint,
            InceptionCheckpoint::CustodyConfirmed { .. }
        ) {
            anyhow::bail!("custody confirmation is required before publishing entry 0");
        }
        serde_json::from_value(self.submit_body.clone())
            .map_err(|error| anyhow::anyhow!("persisted inception draft is invalid: {error}"))
    }

    pub(crate) fn record_inception_accepted(
        &mut self,
        operation_ref: String,
        accepted_head_digest: String,
    ) -> anyhow::Result<()> {
        if !matches!(
            self.checkpoint,
            InceptionCheckpoint::CustodyConfirmed { .. }
        ) || operation_ref.trim().is_empty()
            || !valid_digest(&accepted_head_digest)
        {
            anyhow::bail!("entry 0 acceptance evidence is invalid or out of order");
        }
        self.checkpoint = InceptionCheckpoint::InceptionAccepted {
            operation_ref,
            accepted_head_digest,
        };
        Ok(())
    }

    pub(crate) fn self_pcr_bootstrap_request(
        &self,
        recovery_mnemonic: &str,
        passphrase: &str,
        trust_domain: arkret_sdk::TypedTrustDomainId,
        authorize: arkret_sdk::Event,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitRequestBody> {
        if !matches!(
            self.checkpoint,
            InceptionCheckpoint::InceptionAccepted { .. }
        ) {
            anyhow::bail!("entry 0 must be accepted before self PCR bootstrap");
        }
        self.ensure_recovery_secret_matches(recovery_mnemonic, passphrase)?;
        let keys = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_mnemonic,
            passphrase,
            0,
        )?;
        let principal_id = arkret_sdk::Did::new(self.did.clone())?;
        let realm_id =
            arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
        let create_event_id =
            arkret_sdk::EventId::new(format!("ak:event:{}", self.idempotency.pcr_bootstrap))?;
        let mut create = arkret_sdk::identity::build_self_principal_pcr_create(
            arkret_sdk::identity::SelfPrincipalPcrCreateInput {
                principal_id,
                realm_id,
                trust_domain,
                did_inception_ref: arkret_sdk::EventRef::new(
                    format!("{}#entry-0", self.did),
                    arkret_sdk::identity::DID_INCEPTION_REF_ROLE,
                ),
                event_id: create_event_id,
                created_at: self.prepared_at,
                hlc: arkret_sdk::Hlc::new(self.pcr_bootstrap_hlc.clone())?,
            },
        )?;
        let root_controller = self
            .root_verification_method
            .split_once('#')
            .map_or(self.root_verification_method.as_str(), |(controller, _)| {
                controller
            });
        let signer = arkret_sdk::signatures::Ed25519MoveSigner::from_did_key_seed(
            keys.root_seed,
            arkret_sdk::Did::new(root_controller.to_owned())?,
            self.root_verification_method.clone(),
        );
        arkret_sdk::signatures::sign_event(
            &mut create,
            &signer,
            &self.root_verification_method,
            arkret_sdk::signatures::SignEventOptions::new().with_created_at(self.prepared_at),
        )?;
        arkret_sdk::identity::self_principal_bootstrap_submit_request(create, authorize)
            .map_err(anyhow::Error::from)
    }

    pub(crate) fn record_bootstrap_accepted(
        &mut self,
        receipt_id: String,
        create_event_id: String,
        authorize_event_id: String,
    ) -> anyhow::Result<()> {
        if !matches!(
            self.checkpoint,
            InceptionCheckpoint::InceptionAccepted { .. }
        ) || !receipt_id.starts_with("ak:receipt:")
            || !create_event_id.starts_with("ak:event:")
            || !authorize_event_id.starts_with("ak:event:")
            || create_event_id == authorize_event_id
        {
            anyhow::bail!("PCR bootstrap acceptance evidence is invalid or out of order");
        }
        self.checkpoint = InceptionCheckpoint::BootstrapAccepted {
            receipt_id,
            create_event_id,
            authorize_event_id,
        };
        Ok(())
    }

    pub(crate) fn record_recovery_material_accepted(
        &mut self,
        recovery_policy_ref: arkret_sdk::RecoveryPolicyRef,
        did_recovery_backup_id: String,
    ) -> anyhow::Result<()> {
        if !matches!(
            self.checkpoint,
            InceptionCheckpoint::BootstrapAccepted { .. }
        ) || !did_recovery_backup_id.starts_with("ak:backup:")
        {
            anyhow::bail!("recovery material acceptance evidence is invalid or out of order");
        }
        self.checkpoint = InceptionCheckpoint::RecoveryMaterialAccepted {
            recovery_policy_ref,
            did_recovery_backup_id,
        };
        Ok(())
    }

    pub(crate) fn recovery_material_pending(&self) -> bool {
        !matches!(
            self.checkpoint,
            InceptionCheckpoint::RecoveryMaterialAccepted { .. }
        )
    }

    pub(crate) fn permits_post_bootstrap_persistent_write(&self) -> bool {
        !self.recovery_material_pending()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedArtifact {
    pub(crate) artifact_ref: String,
    pub(crate) canonical_digest: String,
    pub(crate) accepted_at: DateTime<Utc>,
}

impl AcceptedArtifact {
    fn validate(&self) -> anyhow::Result<()> {
        if self.artifact_ref.trim().is_empty() || !valid_digest(&self.canonical_digest) {
            anyhow::bail!("accepted artifact requires a reference and canonical sha256 digest");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSeriesHandoff {
    pub(crate) backup_class: String,
    pub(crate) previous_series_id: String,
    pub(crate) replacement: Option<AcceptedArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EnrollmentAuthorityHandoffStage {
    CustodyConfirmed,
    BridgeEntryAccepted { entry: AcceptedArtifact },
    NewRootEntryAccepted { entry: AcceptedArtifact },
    ReanchorAccepted { batch_receipt: AcceptedArtifact },
    PolicyAccepted { policy: AcceptedArtifact },
    BackupSeriesRewrapping,
    ActiveSeriesPointersAccepted { pointers: Vec<AcceptedArtifact> },
    OldPolicyKeyRevoked { revocation: AcceptedArtifact },
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentAuthorityRecoveryHandoff {
    pub(crate) principal_id: String,
    pub(crate) old_recovery_policy_ref: arkret_sdk::RecoveryPolicyRef,
    pub(crate) target_root_generation: u64,
    pub(crate) idempotency: BTreeMap<String, String>,
    pub(crate) backup_series: Vec<BackupSeriesHandoff>,
    pub(crate) stage: EnrollmentAuthorityHandoffStage,
}

impl EnrollmentAuthorityRecoveryHandoff {
    pub(crate) fn new(
        principal_id: String,
        old_recovery_policy_ref: arkret_sdk::RecoveryPolicyRef,
        target_root_generation: u64,
        active_backup_series: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        if principal_id.trim().is_empty() || target_root_generation < 2 {
            anyhow::bail!("B-model recovery handoff inputs are invalid");
        }
        let mut identities = BTreeSet::new();
        let mut backup_series = Vec::new();
        for (backup_class, previous_series_id) in active_backup_series {
            if !matches!(
                backup_class.as_str(),
                "did_recovery" | "secret_storage" | "mls_history"
            ) || previous_series_id.trim().is_empty()
                || !identities.insert((backup_class.clone(), previous_series_id.clone()))
            {
                anyhow::bail!("active backup series set is invalid");
            }
            backup_series.push(BackupSeriesHandoff {
                backup_class,
                previous_series_id,
                replacement: None,
            });
        }
        if !["did_recovery", "secret_storage", "mls_history"]
            .into_iter()
            .all(|class| {
                backup_series
                    .iter()
                    .any(|series| series.backup_class == class)
            })
        {
            anyhow::bail!("handoff must enumerate every active recovery backup class");
        }
        let idempotency = [
            "bridge_entry",
            "new_root_entry",
            "reanchor",
            "recovery_policy",
            "active_series_pointers",
            "old_policy_revoke",
        ]
        .into_iter()
        .map(|operation| (operation.to_owned(), crate::operation::uuid_v7()))
        .collect();
        Ok(Self {
            principal_id,
            old_recovery_policy_ref,
            target_root_generation,
            idempotency,
            backup_series,
            stage: EnrollmentAuthorityHandoffStage::CustodyConfirmed,
        })
    }

    pub(crate) fn record_bridge_entry(&mut self, entry: AcceptedArtifact) -> anyhow::Result<()> {
        entry.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::CustodyConfirmed
        ) {
            anyhow::bail!("bridge entry is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::BridgeEntryAccepted { entry };
        Ok(())
    }

    pub(crate) fn record_new_root_entry(&mut self, entry: AcceptedArtifact) -> anyhow::Result<()> {
        entry.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::BridgeEntryAccepted { .. }
        ) {
            anyhow::bail!("new-root entry is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::NewRootEntryAccepted { entry };
        Ok(())
    }

    pub(crate) fn record_reanchor(
        &mut self,
        batch_receipt: AcceptedArtifact,
    ) -> anyhow::Result<()> {
        batch_receipt.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::NewRootEntryAccepted { .. }
        ) {
            anyhow::bail!("reanchor is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::ReanchorAccepted { batch_receipt };
        Ok(())
    }

    pub(crate) fn record_policy(&mut self, policy: AcceptedArtifact) -> anyhow::Result<()> {
        policy.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::ReanchorAccepted { .. }
        ) {
            anyhow::bail!("new recovery policy is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::PolicyAccepted { policy };
        Ok(())
    }

    pub(crate) fn begin_backup_rewrap(&mut self) -> anyhow::Result<()> {
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::PolicyAccepted { .. }
        ) {
            anyhow::bail!("backup rewrap is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::BackupSeriesRewrapping;
        Ok(())
    }

    pub(crate) fn record_rewrapped_series(
        &mut self,
        backup_class: &str,
        previous_series_id: &str,
        replacement: AcceptedArtifact,
    ) -> anyhow::Result<()> {
        replacement.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::BackupSeriesRewrapping
        ) {
            anyhow::bail!("backup-series replacement is out of order");
        }
        let series = self
            .backup_series
            .iter_mut()
            .find(|series| {
                series.backup_class == backup_class
                    && series.previous_series_id == previous_series_id
            })
            .ok_or_else(|| anyhow::anyhow!("backup series was not in the accepted active set"))?;
        match &series.replacement {
            Some(existing) if existing == &replacement => return Ok(()),
            Some(_) => anyhow::bail!("backup series already has different accepted replacement"),
            None => series.replacement = Some(replacement),
        }
        Ok(())
    }

    pub(crate) fn record_active_series_pointers(
        &mut self,
        pointers: Vec<AcceptedArtifact>,
    ) -> anyhow::Result<()> {
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::BackupSeriesRewrapping
        ) || self
            .backup_series
            .iter()
            .any(|series| series.replacement.is_none())
        {
            anyhow::bail!("all active backup series must be rewrapped before pointer advance");
        }
        if pointers.len() != self.backup_series.len() {
            anyhow::bail!("pointer evidence must cover every active backup series");
        }
        for pointer in &pointers {
            pointer.validate()?;
        }
        self.stage = EnrollmentAuthorityHandoffStage::ActiveSeriesPointersAccepted { pointers };
        Ok(())
    }

    pub(crate) fn record_old_policy_key_revoked(
        &mut self,
        revocation: AcceptedArtifact,
    ) -> anyhow::Result<()> {
        revocation.validate()?;
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::ActiveSeriesPointersAccepted { .. }
        ) {
            anyhow::bail!("old recovery policy key revocation is out of order");
        }
        self.stage = EnrollmentAuthorityHandoffStage::OldPolicyKeyRevoked { revocation };
        Ok(())
    }

    pub(crate) fn complete(&mut self) -> anyhow::Result<()> {
        if !matches!(
            self.stage,
            EnrollmentAuthorityHandoffStage::OldPolicyKeyRevoked { .. }
        ) {
            anyhow::bail!("recovery handoff cannot complete before old-key revocation");
        }
        self.stage = EnrollmentAuthorityHandoffStage::Complete;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identity_model", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RecoveryWorkflow {
    CrossSigningReset { checkpoint: serde_json::Value },
    EnrollmentAuthorityHandoff(EnrollmentAuthorityRecoveryHandoff),
}

impl RecoveryWorkflow {
    pub(crate) fn ensure_model(&self, model: PrincipalAuthorityModel) -> anyhow::Result<()> {
        if matches!(
            (self, model),
            (
                Self::CrossSigningReset { .. },
                PrincipalAuthorityModel::CrossSigning
            ) | (
                Self::EnrollmentAuthorityHandoff(_),
                PrincipalAuthorityModel::EnrollmentAuthority
            )
        ) {
            return Ok(());
        }
        anyhow::bail!("A-model and B-model recovery workflows are mutually exclusive")
    }
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(reference: &str, byte: char) -> AcceptedArtifact {
        AcceptedArtifact {
            artifact_ref: reference.to_owned(),
            canonical_digest: format!("sha256:{}", byte.to_string().repeat(64)),
            accepted_at: Utc::now(),
        }
    }

    #[test]
    fn public_inception_draft_requires_matching_custody_confirmation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let endpoint = Url::parse("https://principal.example/").unwrap();
        let mut draft = PublicPrincipalInceptionDraft::prepare_from_bip39(
            mnemonic,
            "",
            PreparePrincipalInception {
                principal_endpoint: &endpoint,
                local_id: "alice",
                also_known_as: &[],
                version_time: Utc::now(),
                enrollment: PrincipalEnrollmentInput::ExternalAuthority {
                    authority_did: "did:web:auth.example",
                },
            },
        )
        .unwrap();
        assert!(draft.did_operation_submission().is_err());
        draft
            .confirm_words_reentered(mnemonic, mnemonic, "")
            .unwrap();
        assert!(draft.did_operation_submission().is_ok());
        let persisted = serde_json::to_string(&draft).unwrap();
        assert!(!persisted.contains("abandon"));
        for forbidden in ["root_seed", "recovery_proof_seed", "backup_hpke_ikm"] {
            assert!(!persisted.contains(forbidden));
        }
    }

    #[test]
    fn handoff_refuses_pointer_before_every_active_series_is_rewrapped() {
        let mut handoff = EnrollmentAuthorityRecoveryHandoff::new(
            "did:webvh:example:alice".to_owned(),
            arkret_sdk::RecoveryPolicyRef {
                policy_id: arkret_sdk::PolicyId::new(
                    "ak:policy:01904100-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
                policy_version: 1,
            },
            2,
            vec![
                ("did_recovery".to_owned(), "series-did".to_owned()),
                ("secret_storage".to_owned(), "series-secret".to_owned()),
                ("mls_history".to_owned(), "series-mls".to_owned()),
            ],
        )
        .unwrap();
        handoff
            .record_bridge_entry(artifact("entry-1", '1'))
            .unwrap();
        handoff
            .record_new_root_entry(artifact("entry-2", '2'))
            .unwrap();
        handoff
            .record_reanchor(artifact("ak:receipt:reanchor", '3'))
            .unwrap();
        handoff
            .record_policy(artifact("ak:policy:new", '4'))
            .unwrap();
        handoff.begin_backup_rewrap().unwrap();
        handoff
            .record_rewrapped_series(
                "did_recovery",
                "series-did",
                artifact("series-did-new", '5'),
            )
            .unwrap();
        assert!(
            handoff
                .record_active_series_pointers(vec![artifact("pointer", '6')])
                .is_err()
        );
    }

    #[test]
    fn recovery_models_are_mutually_exclusive() {
        let workflow = RecoveryWorkflow::CrossSigningReset {
            checkpoint: serde_json::json!({"stage": "prepared"}),
        };
        assert!(
            workflow
                .ensure_model(PrincipalAuthorityModel::EnrollmentAuthority)
                .is_err()
        );
    }
}
