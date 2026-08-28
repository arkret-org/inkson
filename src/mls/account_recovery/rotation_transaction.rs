use anyhow::{Context, Result, anyhow};
pub(super) use arkret_models_collaboration::events_payloads::key_backup::ControllerBackupTrustAnchor;
use arkret_models_collaboration::events_payloads::key_backup::resolve_controller_backup_trust_anchor;
use arkret_models_crypto::{BackupKind, BackupSeriesEraseRequestBody, BackupSeriesEraseStatus};
use arkret_wire::{
    BackupObjectRef, BackupRotationKind, BackupSeriesId, Base64UrlString, Did,
    EventsSubmitBatchRequestBody, Hash, LeaseBasisRef, RiskTier, SchemaId, SecurityTransactionStep,
    TransactionId, UnsignedClientStepAttestation,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};
use garth::{PutSecretOptions, SecretClass, SecretDurability, SecureKeyStore};
use serde_json::Value;
use zeroize::Zeroizing;

use super::backup_body::build_mls_account_secret_backup_body_with_kek_and_version;
use super::selection::{active_series_id_for_backup_class, iter_backup_bodies};
use super::series::fresh_backup_id;
use crate::recovery_crypto::derive_vault_kek;

const PENDING_ROTATION_INDEX_KEY: &str = "security_rotation.pending.v1";

pub(crate) struct CompletedSecurityRotation {
    pub(crate) transaction_id: TransactionId,
    pub(crate) new_secret_version: u32,
    pub(crate) replacement_backup_count: usize,
}

pub(crate) struct PreparedRotationBackupMaterial {
    pub(crate) rotation: crate::mls::runtime::AccountMlsSecretRotation,
    pub(crate) new_secret_commitment: Hash,
    pub(crate) classes: Vec<PreparedRotationBackupClass>,
}

pub(crate) struct PreparedRotationBackupClass {
    pub(crate) backup_kind: BackupRotationKind,
    pub(crate) previous_series_id: BackupSeriesId,
    pub(crate) new_series_id: BackupSeriesId,
    pub(crate) new_backup_bodies: Vec<arkret_sdk::KeyBackup>,
    pub(crate) old_backups: Vec<BackupObjectRef>,
}

pub(crate) fn prepare_rotation_backup_material(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &str,
    recovery_words: &str,
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    list_payload: &Value,
    signer: &std::sync::Arc<crate::event_signer::InksonEventSigner>,
    trust_anchor: &ControllerBackupTrustAnchor,
) -> Result<PreparedRotationBackupMaterial> {
    let normalized = crate::recovery_crypto::normalize_recovery_key_input(recovery_words)
        .ok_or_else(|| anyhow!("a valid 24-word Recovery Key is required"))?;
    let rotation = crate::mls::runtime::prepare_account_mls_secret_rotation(
        secure_store,
        authority,
        snapshots,
    )
    .map_err(|error| anyhow!(error.user_message()))?;
    if !rotation.failed_realms.is_empty() {
        return Err(anyhow!(
            "security rotation cannot omit locally held MLS history Realms"
        ));
    }

    let kek = derive_vault_kek(normalized.as_bytes()).context("derive recovery KEK")?;
    let account_backup_id = fresh_backup_id();
    let account_body = build_mls_account_secret_backup_body_with_kek_and_version(
        &account_backup_id,
        actor_id,
        device_id,
        &kek,
        &rotation.new_secret,
        rotation.new_version,
    )?;
    let account_body = sign_rotation_key_backup(account_body, signer, trust_anchor)?;
    let secret_storage = prepare_class(
        list_payload,
        BackupRotationKind::SecretStorage,
        "secret_storage",
        vec![account_body],
    )?;

    let commitment = Hash::new(arkret_sdk::canonical::sha256_digest(
        &arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
            "domain": "org.arkret.inkson.account_mls_secret_commitment.v1",
            "secret": rotation.new_secret,
        }))?,
    ))?;

    Ok(PreparedRotationBackupMaterial {
        rotation,
        new_secret_commitment: commitment,
        classes: vec![secret_storage],
    })
}

fn sign_rotation_key_backup(
    envelope: arkret_sdk::KeyBackup,
    signer: &std::sync::Arc<crate::event_signer::InksonEventSigner>,
    trust_anchor: &ControllerBackupTrustAnchor,
) -> Result<arkret_sdk::KeyBackup> {
    let device_id = signer
        .device_id()
        .ok_or_else(|| anyhow!("active key backup signer has no bound device id"))?;
    let auth = arkret_sdk::UnsignedKeyBackupAuthData::new(
        arkret_sdk::DeviceId::new(device_id.to_owned())?,
        arkret_sdk::DidUrl::new(signer.verification_method().to_owned())
            .map_err(anyhow::Error::msg)?,
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
        trust_anchor.authorize_event_id.clone(),
    )?;
    let unsigned = arkret_sdk::UnsignedKeyBackup::new(envelope, auth)?;
    let signature = Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&unsigned.signing_payload_bytes()?)?),
    )
    .map_err(anyhow::Error::msg)?;
    unsigned
        .attach_signature(signature)
        .map_err(anyhow::Error::from)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_device_revoke_security_rotation(
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    state_store: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    current_device_id: &str,
    target_device_id: &str,
    recovery_words: &str,
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<CompletedSecurityRotation> {
    if current_device_id == target_device_id {
        return Err(anyhow!("a device cannot revoke itself"));
    }
    if let Some(pending) = load_pending_rotation(secure_store.as_ref(), target_device_id)? {
        if pending.actor_id != actor_id || pending.current_device_id != current_device_id {
            return Err(anyhow!(
                "pending security rotation belongs to a different actor or controller device"
            ));
        }
        return resume_device_revoke_security_rotation(
            api,
            secure_store,
            state_store,
            authority,
            actor_id,
            current_device_id,
            target_device_id,
            pending.transaction_id,
        )
        .await;
    }
    let http = api.sdk_http_client()?;
    let submitter = api.event_submitter()?;
    let list_payload = super::restore::fetch_mls_restore_payload(api, actor_id).await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let trust_anchor =
        current_controller_backup_trust_anchor(&http, actor_id, current_device_id).await?;
    let prepared = prepare_rotation_backup_material(
        secure_store.as_ref(),
        authority,
        actor_id,
        current_device_id,
        recovery_words,
        snapshots,
        &list_payload,
        &signer,
        &trust_anchor,
    )?;

    let principal = Did::new(actor_id.to_owned())?;
    let control_realm =
        crate::identity::principal_control::resolve_accepted(&http, &principal).await?;
    let frontier = submitter
        .seals_frontier_realm_view(control_realm.as_str())
        .await?;
    // The active-series pointer binds the accepted Seal's own signed roots, so
    // the frontier leaf is resolved rather than trusting a service root hint.
    let frontier_seal = submitter
        .seals_frontier_realm_head(control_realm.as_str())
        .await?;
    let revoke = crate::operation::ak_ops::device_revoke(
        control_realm.as_str(),
        actor_id,
        target_device_id,
        current_device_id,
        "user_request",
    )?
    .seal_basis(frontier.seal_basis())
    .build_sdk_event(current_device_id)?;
    let mut pointer_events = Vec::with_capacity(prepared.classes.len());
    for class in &prepared.classes {
        pointer_events.push(build_active_series_event(
            &control_realm,
            actor_id,
            class.backup_kind,
            class.new_series_id.as_str(),
            active_pointer_version(&list_payload, class.backup_kind)? + 1,
            std::slice::from_ref(&class.previous_series_id),
            &frontier_seal,
            &trust_anchor,
        )?);
    }
    let mut all_events = Vec::with_capacity(1 + pointer_events.len());
    all_events.push(revoke.into_intent());
    all_events.extend(
        pointer_events
            .into_iter()
            .map(crate::operation::LocalOperation::into_intent),
    );
    let signed_events = submitter.author_independent_events(all_events).await?;
    let envelopes = signed_events
        .iter()
        .map(|event| event.event().clone())
        .collect::<Vec<_>>();
    let digest_suites = signed_events
        .iter()
        .map(arkret_sdk::AuthoredEvent::digest_suite)
        .collect::<Vec<_>>();
    crate::authorization_lease::acquire_for_events(&http, &envelopes, &digest_suites).await?;
    let mut submissions = Vec::with_capacity(envelopes.len());
    for (event, digest_suite) in envelopes.iter().zip(digest_suites.iter().copied()) {
        submissions.push(
            crate::authorization_lease::delayed_initial_submission(&http, event, digest_suite)
                .await?,
        );
    }
    let revoke_submission = EventsSubmitBatchRequestBody {
        events: vec![submissions.remove(0)],
    };
    let drafts = prepared
        .classes
        .iter()
        .zip(submissions)
        .map(
            |(class, submission)| crate::fresh_device_recovery::SecurityRotationBackupDraft {
                backup_kind: class.backup_kind,
                previous_series_id: class.previous_series_id.clone(),
                new_series_id: class.new_series_id.clone(),
                new_backup_bodies: class.new_backup_bodies.clone(),
                active_series_submission: EventsSubmitBatchRequestBody {
                    events: vec![submission],
                },
                old_backups: class.old_backups.clone(),
            },
        )
        .collect();
    let transaction_id =
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?;
    let principal = crate::mls_api_helpers::principal_core_id(principal.as_str())?;
    let create = crate::fresh_device_recovery::SecurityRotationDraft {
        transaction_id: transaction_id.clone(),
        principal_id: principal,
        expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
        revoke_submission,
        new_secret_commitment: prepared.new_secret_commitment.clone(),
        backup_rotations: drafts,
    }
    .into_create_request()?;

    let staged = Zeroizing::new(serde_json::to_vec(&StagedRotationSecret::from_rotation(
        &prepared.rotation,
    )?)?);
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let staged_ref = transaction_store
        .stage_secret(&transaction_id, staged)
        .await
        .map_err(anyhow::Error::from)?;
    if let Err(error) = save_pending_rotation(
        secure_store.as_ref(),
        target_device_id,
        &PendingRotation {
            transaction_id: transaction_id.clone(),
            actor_id: actor_id.to_owned(),
            current_device_id: current_device_id.to_owned(),
        },
    )
    .await
    {
        let _ =
            garth::SecurityTransactionStore::clear_staged_secret(&transaction_store, &staged_ref);
        return Err(error);
    }

    let engine = crate::security_transaction::security_transaction_engine(
        http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::DeviceRevokeSecurityRotation::new(engine);
    let mut transaction = workflow
        .create_or_resume(create, staged_ref)
        .await
        .map_err(anyhow::Error::from)?;
    drive_security_rotation(
        api,
        secure_store,
        state_store,
        authority,
        actor_id,
        current_device_id,
        target_device_id,
        &mut transaction,
    )
    .await
}

async fn resume_device_revoke_security_rotation(
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    state_store: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    current_device_id: &str,
    target_device_id: &str,
    transaction_id: TransactionId,
) -> Result<CompletedSecurityRotation> {
    let http = api.sdk_http_client()?;
    let engine =
        crate::security_transaction::security_transaction_engine(http, secure_store.clone());
    let workflow = crate::fresh_device_recovery::DeviceRevokeSecurityRotation::new(engine);
    let mut transaction = match workflow
        .retry_byte_identical_pending(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        Some(transaction) => transaction,
        None => workflow
            .refresh(&transaction_id)
            .await
            .map_err(anyhow::Error::from)?,
    };
    drive_security_rotation(
        api,
        secure_store,
        state_store,
        authority,
        actor_id,
        current_device_id,
        target_device_id,
        &mut transaction,
    )
    .await
}

async fn drive_security_rotation(
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    current_device_id: &str,
    target_device_id: &str,
    transaction: &mut arkret_wire::SecurityTransaction,
) -> Result<CompletedSecurityRotation> {
    let http = api.sdk_http_client()?;
    let submitter = api.event_submitter()?;
    let principal = Did::new(actor_id.to_owned())?;
    let control_realm =
        crate::identity::principal_control::resolve_accepted(&http, &principal).await?;
    let transaction_id = transaction.transaction_id.clone();
    let engine = crate::security_transaction::security_transaction_engine(
        http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::DeviceRevokeSecurityRotation::new(engine);
    if transaction.is_completed() {
        clear_pending_rotation(secure_store.as_ref(), target_device_id)?;
        let version =
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)?
                .map(|secret| secret.version)
                .ok_or_else(|| {
                    anyhow!("completed security rotation has no committed local MLS secret")
                })?;
        return Ok(CompletedSecurityRotation {
            transaction_id,
            new_secret_version: version,
            replacement_backup_count: rotation_backup_count(transaction)?,
        });
    }
    while matches!(
        transaction.next_required_step()?,
        Some(
            SecurityTransactionStep::Revoke
                | SecurityTransactionStep::UploadNewMaterial
                | SecurityTransactionStep::SwitchAuthoritativePointer
        )
    ) {
        *transaction = workflow
            .continue_server_step(transaction)
            .await
            .map_err(anyhow::Error::from)?;
    }
    let plan = transaction
        .security_rotation_plan()
        .ok_or_else(|| anyhow!("server returned a non-rotation transaction plan"))?
        .clone();
    if transaction.next_required_step()? == Some(SecurityTransactionStep::EraseOldMaterial) {
        let digest_suite = state_store
            .read()
            .trusted_mls_governance_checkpoint(control_realm.as_str())
            .ok_or_else(|| anyhow!("security rotation has no verified PCR governance checkpoint"))?
            .live_digest_suite;
        let erase_frontier = submitter
            .seals_frontier_realm_view(control_realm.as_str())
            .await?;
        let erase_basis_leaf = erase_frontier.sole_leaf()?.clone();
        let erase_lease = crate::authorization_lease::acquire_for_intent(
            &http,
            arkret_wire::AuthorizationLeaseIssueIntent {
                scope_ref: arkret_sdk::ScopeRef::Realm {
                    realm_id: control_realm.clone(),
                },
                action: arkret_sdk::CapabilityActionId::SELF_KEYS_BACKUP_SERIES_COMMAND_ERASE_V1
                    .to_owned(),
                authorization_rule_id: "realm_admission".to_owned(),
                risk_tier: RiskTier::High,
                basis_ref: LeaseBasisRef::Seal(erase_basis_leaf),
            },
            digest_suite,
        )
        .await?;
        let erase_request = BackupSeriesEraseRequestBody {
            transaction_id: transaction.transaction_id.clone(),
            transaction_request_digest: transaction.request_digest.clone(),
            prepared_plan_digest: transaction.prepared_plan_digest.clone(),
            erase_confirmation_digest: plan.erase_confirmation_digest.clone(),
            series: plan
                .backup_rotations
                .iter()
                .map(|rotation| rotation.binding.clone())
                .collect(),
            authorization_lease: erase_lease,
            cba_proof_bundles: Vec::new(),
        };
        let erase = match workflow
            .retry_pending_erase(&transaction.transaction_id)
            .await
            .map_err(anyhow::Error::from)?
        {
            Some(outcome) => outcome,
            None => workflow
                .erase_old_series(&transaction.transaction_id, &erase_request)
                .await
                .map_err(anyhow::Error::from)?,
        };
        if erase.status != BackupSeriesEraseStatus::Complete {
            return Err(anyhow!(
                "old backup series erasure is incomplete and remains retryable"
            ));
        }
        *transaction = workflow
            .refresh(&transaction.transaction_id)
            .await
            .map_err(anyhow::Error::from)?;
    }
    if transaction.next_required_step()? != Some(SecurityTransactionStep::LocalCommit) {
        return Err(anyhow!("security rotation did not reach local commit"));
    }

    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let staged = transaction_store
        .load_staged_secret(&transaction.transaction_id)
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| anyhow!("staged MLS rotation material is unavailable; refusing commit"))?;
    let staged: StagedRotationSecret =
        serde_json::from_slice(staged.as_slice()).context("decode staged MLS rotation material")?;
    let rotation = staged.into_rotation();
    crate::mls::runtime::commit_account_mls_secret_rotation(
        &mut state_store.write(),
        secure_store.as_ref(),
        authority,
        &rotation,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    let local_commit = arkret_models_crypto::SecurityRotationLocalCommit {
        schema: SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1.to_owned(),
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        local_commit_digest: plan.local_commit_digest.clone(),
        erase_confirmation_digest: plan.erase_confirmation_digest.clone(),
        device_id: arkret_sdk::DeviceId::new(current_device_id.to_owned())?,
        committed_at: crate::clock::now_utc(),
    };
    let artifact = arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotationLocalCommit(
        local_commit,
    );
    let attestation_digest = Hash::new(arkret_sdk::canonical::canonical_sha256(&artifact)?)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required for local commit"))?;
    let attestation = UnsignedClientStepAttestation::new(
        SecurityTransactionStep::LocalCommit,
        plan.local_commit_digest.as_str().to_owned(),
        transaction.transaction_id.clone(),
        transaction.request_digest.clone(),
        transaction.prepared_plan_digest.clone(),
        attestation_digest,
        artifact,
        arkret_sdk::DidUrl::new(signer.verification_method().to_owned())
            .map_err(anyhow::Error::msg)?,
    )?;
    let signature =
        arkret_sdk::NonEmptyString::new(signer.detached_jws_over(&attestation.signing_bytes()?)?)
            .map_err(anyhow::Error::msg)?;
    let attestation = attestation.attach_signature(signature)?;
    let completed = workflow
        .continue_with_signed_local_commit(
            &transaction.transaction_id,
            &arkret_models_crypto::SecurityTransactionContinueRequest {
                request_digest: transaction.request_digest.clone(),
                prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                expected_accepted_step_count: transaction.accepted_steps.len().try_into()?,
                client_attestation: Some(attestation),
            },
        )
        .await
        .map_err(anyhow::Error::from)?;
    if !completed.is_completed() {
        return Err(anyhow!("security rotation local commit was not accepted"));
    }
    clear_pending_rotation(secure_store.as_ref(), target_device_id)?;
    Ok(CompletedSecurityRotation {
        transaction_id,
        new_secret_version: rotation.new_version,
        replacement_backup_count: plan
            .backup_rotations
            .iter()
            .map(|rotation| rotation.binding.new_backups.len())
            .sum(),
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StagedRotationSecret {
    previous_version: u32,
    new_version: u32,
    new_secret: String,
    rewrapped_snapshots:
        std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
}

impl StagedRotationSecret {
    fn from_rotation(rotation: &crate::mls::runtime::AccountMlsSecretRotation) -> Result<Self> {
        if rotation.new_secret.is_empty() {
            return Err(anyhow!("staged MLS rotation secret is empty"));
        }
        Ok(Self {
            previous_version: rotation.previous_version,
            new_version: rotation.new_version,
            new_secret: rotation.new_secret.clone(),
            rewrapped_snapshots: rotation.rewrapped_snapshots.clone(),
        })
    }

    fn into_rotation(self) -> crate::mls::runtime::AccountMlsSecretRotation {
        crate::mls::runtime::AccountMlsSecretRotation {
            previous_version: self.previous_version,
            new_version: self.new_version,
            new_secret: self.new_secret,
            rewrapped_snapshots: self.rewrapped_snapshots,
            failed_realms: Vec::new(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingRotation {
    transaction_id: TransactionId,
    actor_id: String,
    current_device_id: String,
}

fn pending_rotation_key(target_device_id: &str) -> Result<String> {
    Ok(crate::secure_key_store::account_scoped_device_key(
        &format!("{PENDING_ROTATION_INDEX_KEY}.{target_device_id}"),
    )?)
}

fn load_pending_rotation(
    secure_store: &dyn SecureKeyStore,
    target_device_id: &str,
) -> Result<Option<PendingRotation>> {
    secure_store
        .get_secret_bytes(&pending_rotation_key(target_device_id)?)?
        .map(|bytes| serde_json::from_slice(&bytes).context("decode pending security rotation"))
        .transpose()
}

async fn save_pending_rotation(
    secure_store: &dyn SecureKeyStore,
    target_device_id: &str,
    pending: &PendingRotation,
) -> Result<()> {
    let bytes = serde_json::to_vec(pending)?;
    secure_store
        .put_secret(
            &pending_rotation_key(target_device_id)?,
            &bytes,
            PutSecretOptions {
                durability: SecretDurability::DurableBeforeReturn,
                class: SecretClass::General,
            },
        )
        .await?;
    Ok(())
}

fn clear_pending_rotation(secure_store: &dyn SecureKeyStore, target_device_id: &str) -> Result<()> {
    match secure_store.delete_secret(&pending_rotation_key(target_device_id)?) {
        Ok(()) | Err(garth::SecureKeyStoreError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn rotation_backup_count(transaction: &arkret_wire::SecurityTransaction) -> Result<usize> {
    let plan = transaction
        .security_rotation_plan()
        .ok_or_else(|| anyhow!("server returned a non-rotation transaction plan"))?;
    Ok(plan
        .backup_rotations
        .iter()
        .map(|rotation| rotation.binding.new_backups.len())
        .sum())
}

/// Resolve the controller trust anchor from the current accepted keys/query
/// projection.
///
/// The mixed-A/B and stale-generation rules live in the SDK
/// (`resolve_controller_backup_trust_anchor`) so every client and the test
/// harnesses share one implementation; this is just the transport call.
/// Nothing here may synthesise a generation number: the whole point of the
/// anchor is that it comes from the authority's current state.
pub(super) async fn current_controller_backup_trust_anchor(
    http: &arkret_sdk::http_client::Client,
    actor_id: &str,
    device_id: &str,
) -> Result<ControllerBackupTrustAnchor> {
    let actor = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let outcome = crate::transport::keys::query_keys(http, actor_id, device_id).await?;
    resolve_controller_backup_trust_anchor(&outcome, &actor, &device)
        .map_err(|error| anyhow!("controller backup trust anchor unavailable: {error}"))
}

fn active_pointer_version(list_payload: &Value, kind: BackupRotationKind) -> Result<u64> {
    let wire_kind = wire_backup_kind(kind);
    list_payload
        .get("active_series")
        .and_then(Value::as_array)
        .and_then(|records| {
            records
                .iter()
                .find(|record| record.get("backup_kind").and_then(Value::as_str) == Some(wire_kind))
        })
        .and_then(|record| record.get("series_pointer_version"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("active {wire_kind} pointer version is unavailable"))
}

pub(super) fn wire_backup_kind(kind: BackupRotationKind) -> &'static str {
    match kind {
        BackupRotationKind::SecretStorage => "secret_storage",
        BackupRotationKind::MlsHistory => "mls_history",
    }
}

pub(super) fn build_active_series_event(
    principal_control_realm_id: &arkret_sdk::RealmId,
    actor_id: &str,
    kind: BackupRotationKind,
    series_id: &str,
    pointer_version: u64,
    previous_series_ids: &[BackupSeriesId],
    frontier: &arkret_sdk::Seal,
    trust_anchor: &ControllerBackupTrustAnchor,
) -> Result<crate::operation::LocalOperation> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let principal_did = Did::new(actor_id.to_owned())?;
    let principal = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let verification_method = signer.verification_method_for_principal(&principal_did)?;
    let backup_kind = match kind {
        BackupRotationKind::SecretStorage => BackupKind::SecretStorage,
        BackupRotationKind::MlsHistory => BackupKind::MlsHistory,
    };
    let unsigned = arkret_sdk::UnsignedKeyBackupActiveSeries::new(
        principal.clone(),
        backup_kind,
        BackupSeriesId::new(series_id.to_owned())?,
        pointer_version,
        previous_series_ids.to_vec(),
        frontier.control_event_set_root.clone(),
        Some(frontier.id.clone()),
        crate::clock::now_utc(),
        verification_method,
        trust_anchor.clone(),
    )?;
    let signature = Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&unsigned.signing_payload_bytes()?)?),
    )
    .map_err(anyhow::Error::msg)?;
    let payload = unsigned.attach_signature(signature)?;
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::KeyBackupActiveSeries>(
        principal_control_realm_id.to_string(),
        actor_id,
        payload,
    )
    .build_sdk_event("inkson")
}

fn prepare_class(
    list_payload: &Value,
    backup_kind: BackupRotationKind,
    wire_kind: &str,
    new_backup_bodies: Vec<arkret_sdk::KeyBackup>,
) -> Result<PreparedRotationBackupClass> {
    let previous_series_id = active_series_id_for_backup_class(list_payload, wire_kind)
        .ok_or_else(|| anyhow!("no authoritative {wire_kind} series is available"))?;
    let previous_series_id = BackupSeriesId::new(previous_series_id.to_owned())?;
    let expected_kind = match backup_kind {
        BackupRotationKind::SecretStorage => BackupKind::SecretStorage,
        BackupRotationKind::MlsHistory => BackupKind::MlsHistory,
    };
    if new_backup_bodies.is_empty()
        || new_backup_bodies
            .iter()
            .any(|body| body.backup_kind != expected_kind)
    {
        return Err(anyhow!(
            "replacement {wire_kind} backups must be non-empty and match their rotation class"
        ));
    }
    let new_series_id = new_backup_bodies[0].series_id.clone();
    if new_backup_bodies
        .iter()
        .any(|body| body.series_id != new_series_id)
    {
        return Err(anyhow!(
            "replacement {wire_kind} backups must share one series_id"
        ));
    }
    if previous_series_id == new_series_id {
        return Err(anyhow!(
            "replacement {wire_kind} series must differ from the active series"
        ));
    }
    let mut old_backups = iter_backup_bodies(list_payload)
        .filter(|body| body.get("backup_kind").and_then(Value::as_str) == Some(wire_kind))
        .filter(|body| {
            body.get("series_id").and_then(Value::as_str) == Some(previous_series_id.as_str())
        })
        .map(backup_ref)
        .collect::<Result<Vec<_>>>()?;
    if old_backups.is_empty() {
        return Err(anyhow!(
            "authoritative {wire_kind} series has no erasable backup objects"
        ));
    }
    old_backups.sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
    Ok(PreparedRotationBackupClass {
        backup_kind,
        previous_series_id,
        new_series_id,
        new_backup_bodies,
        old_backups,
    })
}

fn backup_ref(body: &Value) -> Result<BackupObjectRef> {
    let backup_id = body
        .get("backup_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("old backup omits backup_id"))?;
    let ciphertext_digest = body
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("old backup omits ciphertext_digest"))?;
    Ok(BackupObjectRef {
        backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())?,
        ciphertext_digest: Hash::new(ciphertext_digest.to_owned())?,
    })
}

#[cfg(test)]
mod rotation_resume_tests {
    use super::*;

    #[tokio::test]
    async fn pending_rotation_index_round_trips_and_clears() {
        // pending_rotation_key resolves through the process-global
        // device-seed scope installed by activate().
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let store = garth::MemorySecureKeyStore::new();
        let user_store = crate::secure_key_store::UserLocalStore::new(
            arkret_sdk::PrincipalAuthorityKey::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
            ),
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000011".to_owned())
                .unwrap(),
        )
        .unwrap();
        user_store.activate();
        let target = "ak:device:01964137-0000-7000-8000-000000000022";
        let pending = PendingRotation {
            transaction_id: TransactionId::new(
                "ak:transaction:01964137-0000-7000-8000-000000000033",
            )
            .unwrap(),
            actor_id: "did:webvh:z6mkfixture:alice.example".to_owned(),
            current_device_id: "ak:device:01964137-0000-7000-8000-000000000011".to_owned(),
        };

        save_pending_rotation(&store, target, &pending)
            .await
            .unwrap();
        let restored = load_pending_rotation(&store, target).unwrap().unwrap();
        assert_eq!(restored.transaction_id, pending.transaction_id);
        assert_eq!(restored.actor_id, pending.actor_id);
        assert_eq!(restored.current_device_id, pending.current_device_id);

        clear_pending_rotation(&store, target).unwrap();
        clear_pending_rotation(&store, target).unwrap();
        assert!(load_pending_rotation(&store, target).unwrap().is_none());
    }
}
