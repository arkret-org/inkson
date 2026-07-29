use anyhow::{Context, Result, anyhow};
use arkret_models_crypto::{BackupSeriesEraseRequestBody, BackupSeriesEraseStatus};
use arkret_wire::{
    BackupObjectRef, BackupRotationKind, BackupSeriesId, CLIENT_STEP_ATTESTATION_SIGNED_FIELDS,
    ClientStepAttestation, ClientStepAttestationAuthData, ControlProposalReceipt,
    ControlProposalReceiptKind, Did, EventInitialSubmission, EventsSubmitBatchRequestBody, Hash,
    LeaseBasisRef, ProposalReceiptIssueRequest, RiskTier, SecurityTransactionBinding,
    SecurityTransactionState, SecurityTransactionStep, TransactionId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::prelude::{SyncSignal, WritableExt};
use garth::SecureKeyStore;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::backup_body::build_mls_account_secret_backup_body_with_kek_and_version;
use super::selection::{active_series_id_for_backup_class, iter_backup_bodies};
use super::series::fresh_backup_id;
use crate::recovery_crypto::derive_vault_kek;

const ACTIVE_SERIES_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "actor_id",
    "backup_kind",
    "active_series_id",
    "series_pointer_version",
    "previous_series_ids",
    "frontier_ref",
    "issued_at",
];

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
    pub(crate) new_backup_bodies: Vec<Value>,
    pub(crate) old_backups: Vec<BackupObjectRef>,
}

pub(crate) fn prepare_rotation_backup_material(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    actor_id: &str,
    device_id: &str,
    recovery_words: &str,
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    list_payload: &Value,
) -> Result<PreparedRotationBackupMaterial> {
    let normalized = crate::recovery_crypto::normalize_recovery_key_input(recovery_words)
        .ok_or_else(|| anyhow!("a valid 24-word Recovery Key is required"))?;
    let rotation = crate::mls::runtime::prepare_account_mls_secret_rotation(
        secure_store,
        actor_id,
        device_id,
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
    let secret_storage = prepare_class(
        list_payload,
        BackupRotationKind::SecretStorage,
        "secret_storage",
        vec![account_body],
    )?;

    if rotation.rewrapped_snapshots.is_empty() {
        return Err(anyhow!(
            "security rotation requires at least one replacement MLS history backup"
        ));
    }
    let history_series_id =
        BackupSeriesId::new(format!("ak:backup_series:{}", crate::operation::uuid_v7()))?;
    let mut history_bodies = Vec::with_capacity(rotation.rewrapped_snapshots.len());
    for snapshot in rotation.rewrapped_snapshots.values() {
        let (_, mut body) = crate::mls::runtime::build_mls_history_backup_body_with_secret(
            snapshot,
            actor_id,
            device_id,
            &rotation.new_secret,
        )
        .map_err(|error| anyhow!(error.user_message()))?;
        body["series_id"] = Value::String(history_series_id.as_str().to_owned());
        crate::key_backup::sign_key_backup_with_active_device(&mut body, device_id)
            .context("sign replacement MLS history backup")?;
        history_bodies.push(body);
    }
    history_bodies.sort_by(|left, right| {
        left.get("backup_id")
            .and_then(Value::as_str)
            .cmp(&right.get("backup_id").and_then(Value::as_str))
    });
    let mut mls_history = prepare_class(
        list_payload,
        BackupRotationKind::MlsHistory,
        "mls_history",
        history_bodies,
    )?;
    mls_history.new_series_id = history_series_id;

    let commitment = Hash::new(arkret_sdk::canonical::sha256_digest(
        &arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
            "domain": "ak.account_mls_secret_commitment.v1",
            "secret": rotation.new_secret,
        }))?,
    ))?;

    Ok(PreparedRotationBackupMaterial {
        rotation,
        new_secret_commitment: commitment,
        classes: vec![secret_storage, mls_history],
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_device_revoke_security_rotation(
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    actor_id: &str,
    current_device_id: &str,
    target_device_id: &str,
    recovery_words: &str,
    snapshots: &std::collections::BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
) -> Result<CompletedSecurityRotation> {
    if current_device_id == target_device_id {
        return Err(anyhow!("a device cannot revoke itself"));
    }
    let http = api.sdk_http_client()?;
    let submitter = api.event_submitter()?;
    let coordinator_service_id = Did::new(submitter.service_id().await?)?;
    let list_payload = super::restore::fetch_mls_restore_payload(api).await?;
    let prepared = prepare_rotation_backup_material(
        secure_store.as_ref(),
        actor_id,
        current_device_id,
        recovery_words,
        snapshots,
        &list_payload,
    )?;

    let principal = Did::new(actor_id.to_owned())?;
    let control_realm = arkret_sdk::principal_control_realm_id(&principal);
    let frontier = submitter
        .events_frontier_realm_seal_view(&control_realm)
        .await?;
    let revoke = crate::operation::ak_ops::device_revoke(
        &control_realm,
        actor_id,
        target_device_id,
        current_device_id,
        "user_request",
    )?
    .seal_basis(frontier.seal_basis())
    .build_sdk_event(current_device_id)?;
    let trust_anchor =
        current_controller_backup_trust_anchor(&http, actor_id, current_device_id).await?;
    let mut pointer_events = Vec::with_capacity(prepared.classes.len());
    for class in &prepared.classes {
        pointer_events.push(build_active_series_event(
            actor_id,
            class.backup_kind,
            class.new_series_id.as_str(),
            active_pointer_version(&list_payload, class.backup_kind)? + 1,
            std::slice::from_ref(&class.previous_series_id),
            &frontier,
            &trust_anchor,
        )?);
    }
    let mut all_events = Vec::with_capacity(1 + pointer_events.len());
    all_events.push(revoke);
    all_events.extend(pointer_events);
    let signed_events = submitter.prepare_sdk_events_batch(all_events).await?;
    let leases = crate::authorization_lease::acquire_for_events(&http, &signed_events).await?;
    let mut submissions = Vec::with_capacity(signed_events.len());
    for (event, lease) in signed_events.into_iter().zip(leases) {
        let member = http
            .issue_control_proposal_receipt(&ProposalReceiptIssueRequest {
                event: event.clone(),
                authorization_lease: lease.clone(),
                cba_proof_bundles: Vec::new(),
            })
            .await?
            .member_receipt;
        let receipt = ControlProposalReceipt {
            kind: ControlProposalReceiptKind::ProposalReceipt,
            realm_id: member.realm_id.clone(),
            proposal_digest: member.proposal_digest.clone(),
            received_at: member.received_at,
            decision_due_at: member.decision_due_at,
            absolute_due_at: member.absolute_due_at,
            defer_count: 0,
            authority_set_ref: member.authority_set_ref.clone(),
            member_receipts: vec![member],
        };
        receipt.validate_protocol_bounds()?;
        submissions.push(EventInitialSubmission {
            event,
            authorization_lease: lease,
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: Some(receipt),
        });
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
    let create = crate::fresh_device_recovery::SecurityRotationDraft {
        transaction_id: transaction_id.clone(),
        principal_id: principal,
        expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
        revoke_submission,
        new_secret_commitment: prepared.new_secret_commitment.clone(),
        backup_rotations: drafts,
    }
    .into_create_request(coordinator_service_id)?;

    let staged = Zeroizing::new(serde_json::to_vec(&StagedRotationSecret::from_rotation(
        &prepared.rotation,
    )?)?);
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let staged_ref = transaction_store
        .stage_secret(&transaction_id, staged)
        .await
        .map_err(anyhow::Error::from)?;

    let engine = crate::security_transaction::security_transaction_engine(
        http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::DeviceRevokeSecurityRotation::new(engine);
    let mut transaction = workflow
        .create_or_resume(create, staged_ref)
        .await
        .map_err(anyhow::Error::from)?;
    while matches!(
        transaction.next_required_step,
        Some(
            SecurityTransactionStep::Revoke
                | SecurityTransactionStep::UploadNewMaterial
                | SecurityTransactionStep::SwitchAuthoritativePointer
        )
    ) {
        transaction = workflow
            .continue_server_step(&transaction)
            .await
            .map_err(anyhow::Error::from)?;
    }
    if transaction.next_required_step != Some(SecurityTransactionStep::EraseOldMaterial) {
        return Err(anyhow!(
            "security rotation did not reach the durable erase operation"
        ));
    }
    let SecurityTransactionBinding::SecurityRotation(binding) = transaction.binding.clone() else {
        return Err(anyhow!(
            "server returned a non-rotation transaction binding"
        ));
    };
    let erase_frontier = submitter
        .events_frontier_realm_seal_view(&control_realm)
        .await?;
    let erase_lease = crate::authorization_lease::acquire_for_intent(
        &http,
        arkret_wire::AuthorizationLeaseIssueIntent {
            scope_ref: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(control_realm.clone())?,
            },
            action: "ak.keys.backup_series.erase".to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::High,
            basis_ref: LeaseBasisRef::Seal(erase_frontier.seal_id),
        },
    )
    .await?;
    let erase_request = BackupSeriesEraseRequestBody {
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        erase_confirmation_digest: binding.erase_confirmation_digest.clone(),
        series: binding.backup_rotations.clone(),
        authorization_lease: erase_lease,
        cba_proof_bundles: Vec::new(),
    };
    let erase = workflow
        .erase_old_series(&transaction.transaction_id, &erase_request)
        .await
        .map_err(anyhow::Error::from)?;
    if erase.status != BackupSeriesEraseStatus::Complete {
        return Err(anyhow!(
            "old backup series erasure is incomplete and remains retryable"
        ));
    }
    transaction = workflow
        .refresh(&transaction.transaction_id)
        .await
        .map_err(anyhow::Error::from)?;
    if transaction.next_required_step != Some(SecurityTransactionStep::LocalCommit) {
        return Err(anyhow!("security rotation did not reach local commit"));
    }

    crate::mls::runtime::commit_account_mls_secret_rotation(
        &mut state_store.write(),
        secure_store.as_ref(),
        actor_id,
        &prepared.rotation,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    let local_commit = arkret_models_crypto::SecurityRotationLocalCommit {
        schema: arkret_models_crypto::SECURITY_ROTATION_LOCAL_COMMIT_SCHEMA.to_owned(),
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        local_commit_digest: binding.local_commit_digest.clone(),
        erase_confirmation_digest: binding.erase_confirmation_digest.clone(),
        device_id: arkret_sdk::DeviceId::new(current_device_id.to_owned())?,
        committed_at: crate::clock::now_utc(),
    };
    let artifact = arkret_models_crypto::ClientStepAttestationArtifact::SecurityRotationLocalCommit(
        local_commit,
    );
    let attestation_digest = Hash::new(arkret_sdk::canonical::canonical_sha256(&artifact)?)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required for local commit"))?;
    let mut attestation = ClientStepAttestation {
        step: SecurityTransactionStep::LocalCommit,
        output_ref: binding.local_commit_digest.as_str().to_owned(),
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        attestation_digest,
        artifact,
        auth_data: ClientStepAttestationAuthData {
            verification_method: signer.verification_method().to_owned(),
            alg: "EdDSA".to_owned(),
            signature: "pending".to_owned(),
            signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
    };
    attestation.auth_data.signature = signer.detached_jws_over(&attestation.signing_bytes()?)?;
    let completed = workflow
        .continue_with_signed_local_commit(
            &transaction.transaction_id,
            &arkret_models_crypto::TypedSecurityTransactionContinueRequest {
                request_digest: transaction.request_digest,
                prepared_plan_digest: transaction.prepared_plan_digest,
                expected_next_step: SecurityTransactionStep::LocalCommit,
                client_attestation: Some(attestation),
                participant_request: None,
            },
        )
        .await
        .map_err(anyhow::Error::from)?;
    if completed.state != SecurityTransactionState::Completed {
        return Err(anyhow!("security rotation local commit was not accepted"));
    }
    Ok(CompletedSecurityRotation {
        transaction_id,
        new_secret_version: prepared.rotation.new_version,
        replacement_backup_count: prepared
            .classes
            .iter()
            .map(|class| class.new_backup_bodies.len())
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
}

#[derive(Clone, Debug)]
enum ControllerBackupTrustAnchor {
    SskGeneration(u64),
    DeviceGeneration {
        authorize_event_id: String,
        generation_ref: String,
    },
}

async fn current_controller_backup_trust_anchor(
    http: &arkret_sdk::http_client::Client,
    actor_id: &str,
    device_id: &str,
) -> Result<ControllerBackupTrustAnchor> {
    let actor = Did::new(actor_id.to_owned())?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let outcome = crate::transport::keys::query_keys(http, actor_id, device_id).await?;
    let record = outcome
        .device_keys
        .get(&actor)
        .and_then(|devices| devices.get(&device))
        .ok_or_else(|| anyhow!("current device is absent from keys/query"))?;
    let generation = outcome.device_generations.get(&actor);
    if !record.is_usable_in_generation(generation) {
        return Err(anyhow!(
            "current device is not usable in the active trust generation"
        ));
    }
    match (
        record.cross_signing_binding.as_ref(),
        generation,
        record.authorized_generation_ref.as_ref(),
        record.device_authorize_event_id.as_ref(),
    ) {
        (Some(binding), None, None, _) => {
            let publish = outcome
                .cross_signing
                .get(&actor)
                .ok_or_else(|| anyhow!("keys/query omitted current cross-signing state"))?;
            if publish.generation.get() != binding.ssk_generation {
                return Err(anyhow!("cross-signing generation changed"));
            }
            Ok(ControllerBackupTrustAnchor::SskGeneration(
                binding.ssk_generation,
            ))
        }
        (None, Some(generation), Some(bound), Some(authorize_event_id))
            if generation.device_generation_status
                == arkret_sdk::DeviceGenerationStatus::Active
                && bound.as_str() == generation.current_device_generation_ref.as_str() =>
        {
            Ok(ControllerBackupTrustAnchor::DeviceGeneration {
                authorize_event_id: authorize_event_id.to_string(),
                generation_ref: generation.current_device_generation_ref.to_string(),
            })
        }
        _ => Err(anyhow!("current device trust model is mixed or incomplete")),
    }
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

fn wire_backup_kind(kind: BackupRotationKind) -> &'static str {
    match kind {
        BackupRotationKind::SecretStorage => "secret_storage",
        BackupRotationKind::MlsHistory => "mls_history",
    }
}

fn build_active_series_event(
    actor_id: &str,
    kind: BackupRotationKind,
    series_id: &str,
    pointer_version: u64,
    previous_series_ids: &[BackupSeriesId],
    frontier: &arkret_sdk::RealmSealFrontierView,
    trust_anchor: &ControllerBackupTrustAnchor,
) -> Result<arkret_sdk::Event> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow!("active device signer is required"))?;
    let issued_at = arkret_sdk::canonical::format_timestamp_canonical(crate::clock::now_utc());
    let mut payload = json!({
        "schema": crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA,
        "actor_id": actor_id,
        "backup_kind": wire_backup_kind(kind),
        "active_series_id": series_id,
        "series_pointer_version": pointer_version,
        "previous_series_ids": previous_series_ids,
        "frontier_ref": {
            "frontier_digest": frontier.control_event_set_root,
            "seal_ref": frontier.seal_id
        },
        "issued_at": issued_at,
        "auth_data": {
            "verification_method": signer.verification_method(),
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": ACTIVE_SERIES_SIGNED_FIELDS
        }
    });
    match trust_anchor {
        ControllerBackupTrustAnchor::SskGeneration(generation) => {
            payload["frontier_ref"]["ssk_generation"] = json!(generation);
            payload["auth_data"]["ssk_generation"] = json!(generation);
        }
        ControllerBackupTrustAnchor::DeviceGeneration {
            authorize_event_id,
            generation_ref,
        } => {
            payload["frontier_ref"]["device_generation_ref"] = json!(generation_ref);
            payload["auth_data"]["device_authorize_event_id"] = json!(authorize_event_id);
        }
    }
    let mut unsigned = payload.clone();
    unsigned["auth_data"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("active-series auth_data is malformed"))?
        .remove("signature");
    payload["auth_data"]["signature"] = Value::String(
        URL_SAFE_NO_PAD
            .encode(signer.sign_raw(&crate::canonical::canonical_json_bytes(&unsigned)?)?),
    );
    crate::operation::OperationBuilder::new(
        arkret_sdk::principal_control_realm_id(&Did::new(actor_id.to_owned())?),
        actor_id,
        crate::operation::EventKind::KeyBackupActiveSeries,
    )
    .body(payload)
    .build_sdk_event("inkson")
}

fn prepare_class(
    list_payload: &Value,
    backup_kind: BackupRotationKind,
    wire_kind: &str,
    new_backup_bodies: Vec<Value>,
) -> Result<PreparedRotationBackupClass> {
    let previous_series_id = active_series_id_for_backup_class(list_payload, wire_kind)
        .ok_or_else(|| anyhow!("no authoritative {wire_kind} series is available"))?;
    let previous_series_id = BackupSeriesId::new(previous_series_id.to_owned())?;
    let new_series_id = new_backup_bodies
        .first()
        .and_then(|body| body.get("series_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("replacement {wire_kind} backup omits series_id"))
        .and_then(|value| BackupSeriesId::new(value.to_owned()).map_err(anyhow::Error::from))?;
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
