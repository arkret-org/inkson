//! 6.1 / 6.3 — recovery client orchestration.
//!
//! Pure request builders (unit-tested) + thin async wrappers over
//! [`crate::transport::TransportClient`] that drive the REC-1 recovery flow:
//!
//! - 6.1: fetch + parse the active recovery policy.
//! - 6.3: open a recovery session and sign + submit a `recovery_unlock` proof.
//!
//! Recovery completion is a durable protocol operation and is deliberately not
//! exposed here as a direct HTTP side effect.

use arkret_models_crypto::{
    GenericRecoveryTranscript, RecoveryBackupHpkeSuite, RecoveryKeyAgreementAlgorithm,
    RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse, RecoveryKeyEntry, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicyAuthData, RecoveryPolicySummary, RecoveryProofKind,
    RecoverySignatureAlgorithm, RecoveryTranscriptProofBody, RecoveryUnlockProofBody,
    RecoveryUnlockProofBodyWithSignature, RecoveryUnlockProofKind,
};
use arkret_sdk::{DidUrl, PolicyId, TrustDomainId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::Signer as _;
use serde_json::Value;

use crate::transport::TransportClient;

/// Return the accepted policy from the already-validated transport DTO.
pub fn active_recovery_policy(
    outcome: &RecoveryPolicyActiveOutcome,
) -> Option<RecoveryPolicySummary> {
    outcome
        .active_policy
        .as_ref()
        .filter(|policy| policy.version > 0)
        .cloned()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstBackupGateStatus {
    Satisfied,
    Blocked(FirstBackupGateBlockReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstBackupGateBlockReason {
    NoAcceptedPrincipalControlCommit,
    NoActiveRecoveryPolicy,
}

pub fn first_backup_gate_status(
    accepted_principal_control_commit: bool,
    recovery_policy_outcome: &RecoveryPolicyActiveOutcome,
) -> FirstBackupGateStatus {
    if !accepted_principal_control_commit {
        return FirstBackupGateStatus::Blocked(
            FirstBackupGateBlockReason::NoAcceptedPrincipalControlCommit,
        );
    }
    let Some(policy) = active_recovery_policy(recovery_policy_outcome) else {
        return FirstBackupGateStatus::Blocked(FirstBackupGateBlockReason::NoActiveRecoveryPolicy);
    };
    let _ = policy;
    FirstBackupGateStatus::Satisfied
}

pub async fn verify_recovery_material_evidence(
    api: &TransportClient,
    evidence: &crate::state::RecoveryMaterialEvidence,
) -> anyhow::Result<()> {
    verify_recovery_authority_evidence(api, evidence).await?;
    let policy = api.get_recovery_policy().await?;
    match first_backup_gate_status(true, &policy) {
        FirstBackupGateStatus::Satisfied => Ok(()),
        FirstBackupGateStatus::Blocked(reason) => {
            anyhow::bail!("durable recovery-material evidence is incomplete: {reason:?}")
        }
    }
}

pub async fn verify_recovery_authority_evidence(
    api: &TransportClient,
    evidence: &crate::state::RecoveryMaterialEvidence,
) -> anyhow::Result<()> {
    evidence.pcr_genesis_unit.validate_ordered_envelopes()?;
    if arkret_sdk::project_did_to_core_id(&evidence.principal_did)?
        != evidence.account_id.principal_id
        || evidence.pcr_genesis_unit.create().actor_id
            != arkret_sdk::ActorId::account(evidence.account_id.clone())
        || evidence.pcr_genesis_unit.create().realm_id != evidence.principal_control_realm_id
        || evidence.pcr_genesis_unit.founding_authorize().realm_id
            != evidence.principal_control_realm_id
    {
        anyhow::bail!("durable recovery-material evidence has mixed PCR scope");
    }
    let create = evidence.pcr_genesis_unit.create();
    let authorize = evidence.pcr_genesis_unit.founding_authorize();
    let create_digest = arkret_sdk::Hash::new(
        create.event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
    )?;
    let authorize_digest = arkret_sdk::Hash::new(
        authorize.event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
    )?;
    validate_pcr_genesis_coordinates(
        &evidence.principal_control_realm_id,
        &create.event_id,
        &authorize.event_id,
        &evidence.pcr_genesis_commits,
    )?;
    let [create_ref, authorize_ref] = &evidence.pcr_genesis_commits;

    let http = api.sdk_http_client()?;
    let resolved_create = http.committed_event_get(&create_ref.event_id).await?;
    let resolved_authorize = http.committed_event_get(&authorize_ref.event_id).await?;
    if !create_ref.matches(&resolved_create)
        || !authorize_ref.matches(&resolved_authorize)
        || resolved_authorize
            .commit()
            .validate_successor_of(resolved_create.commit())
            .is_err()
        || !resolved_create.reducer_input().is_some_and(|event| {
            accepted_event_matches_genesis_basis(event, create, &create_digest)
        })
        || !resolved_authorize.reducer_input().is_some_and(|event| {
            accepted_event_matches_genesis_basis(event, authorize, &authorize_digest)
        })
    {
        anyhow::bail!("server no longer resolves the exact committed PCR genesis unit");
    }
    Ok(())
}

fn validate_pcr_genesis_coordinates(
    principal_control_realm_id: &arkret_sdk::RealmId,
    create_event_id: &arkret_sdk::EventId,
    authorize_event_id: &arkret_sdk::EventId,
    commits: &[arkret_wire::CommittedEventRef; 2],
) -> anyhow::Result<()> {
    let [create_ref, authorize_ref] = commits;
    let expected_stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: principal_control_realm_id.clone(),
    };
    if &create_ref.event_id != create_event_id
        || &authorize_ref.event_id != authorize_event_id
        || create_ref.stream_ref != expected_stream
        || authorize_ref.stream_ref != expected_stream
        || create_ref.stream_position != 0
        || authorize_ref.stream_position != 1
        || create_ref.commit_id == authorize_ref.commit_id
    {
        anyhow::bail!("durable PCR genesis coordinates do not name the exact ordered unit");
    }
    Ok(())
}

/// The frozen PCR genesis unit contains producer-authored Events. Resolution
/// returns the accepted producer envelope. Compare its canonical digest and
/// producer-authored fields byte-for-byte; receiver-local admission metadata
/// never becomes part of the Event.
fn accepted_event_matches_genesis_basis(
    accepted: &arkret_sdk::Event,
    authored: &arkret_sdk::Event,
    expected_digest: &arkret_sdk::Hash,
) -> bool {
    let digest_suite = arkret_sdk::DigestSuite::Sha256;
    accepted
        .event_digest_with_digest_suite(digest_suite)
        .ok()
        .and_then(|digest| arkret_sdk::Hash::new(digest).ok())
        .as_ref()
        == Some(expected_digest)
        && crate::event_submit::accepted_event_preserves_authored_envelope(
            accepted,
            authored,
            digest_suite,
        )
        .unwrap_or(false)
}

/// 6.1 — fetch + parse the active recovery policy.
pub async fn fetch_active_recovery_policy(
    api: &TransportClient,
) -> anyhow::Result<Option<RecoveryPolicySummary>> {
    let response = api.get_recovery_policy().await?;
    Ok(active_recovery_policy(&response))
}

pub fn build_signed_genesis_recovery_policy_for_session_device(
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    trust_domain: &str,
    device_id: &arkret_sdk::DeviceId,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<Value> {
    if let Some(signer) = crate::event_signer::active_signer() {
        if signer.device_id() != Some(device_id.as_str()) {
            anyhow::bail!("active signer is not bound to current session device `{device_id}`");
        }
        let verification_method = format!("{principal_did}#{device_id}");
        return build_signed_genesis_recovery_policy_with_raw_signer(
            principal_did,
            account_id,
            trust_domain,
            key_material,
            &verification_method,
            |bytes| signer.sign_raw(bytes),
        );
    }

    let signer = default_principal_scoped_recovery_policy_signer(principal_did, device_id)?;
    build_signed_genesis_recovery_policy_with_signer(
        principal_did,
        account_id,
        trust_domain,
        key_material,
        &signer,
    )
}

fn default_principal_scoped_recovery_policy_signer(
    principal_did: &arkret_sdk::Did,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<crate::event_signer::InksonEventSigner> {
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    let material = crate::secure_key_store::ensure_signing_seed(store.as_ref())
        .map_err(|err| anyhow::anyhow!("ensure recovery policy signing seed failed: {err}"))?;
    Ok(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            material.seed,
            principal_did.as_str(),
            format!("{principal_did}#{device_id}"),
        ),
    )
}

fn build_signed_genesis_recovery_policy_with_signer(
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    trust_domain: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<Value> {
    let verification_method =
        principal_scoped_recovery_policy_verification_method(principal_did, signer)?;
    build_signed_genesis_recovery_policy_with_raw_signer(
        principal_did,
        account_id,
        trust_domain,
        key_material,
        verification_method,
        |bytes| signer.sign_raw(bytes),
    )
}

fn build_signed_genesis_recovery_policy_with_raw_signer(
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    trust_domain: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    verification_method: &str,
    sign_raw: impl Fn(&[u8]) -> Result<Vec<u8>, crate::event_signer::EventSignerError>,
) -> anyhow::Result<Value> {
    let trust_domain = trust_domain.trim();
    let verification_method = verification_method.trim();
    if trust_domain.is_empty() {
        anyhow::bail!("trust_domain is required");
    }
    if arkret_sdk::project_did_to_core_id(principal_did)? != account_id.principal_id {
        anyhow::bail!("recovery policy principal projection does not match account authority");
    }
    principal_scoped_recovery_policy_verification_method_id(principal_did, verification_method)?;
    let issued_at = chrono::Utc::now();
    let key_expires_at = issued_at + chrono::Duration::days(3650);
    let recovery_proof_ref = DidUrl::new(format!("{principal_did}#recovery-proof-0"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let backup_hpke_ref = DidUrl::new(format!("{principal_did}#backup-hpke-0"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let mut typed_policy = RecoveryPolicy {
        schema: arkret_sdk::SchemaId::RECOVERY_POLICY_V1.to_owned(),
        policy_id: PolicyId::new(format!("ak:policy:{}", crate::operation::uuid_v7()))?,
        account_id: account_id.clone(),
        version: 1,
        supersedes_id: None,
        trust_domain: TrustDomainId::new(trust_domain.to_owned())?,
        methods: vec![arkret_sdk::RecoveryMethod::RecoveryUnlock {
            keys: vec![RecoveryKeyEntry {
                verification_method: recovery_proof_ref,
                public_key_multibase: key_material.recovery_proof_public_key_multikey.clone(),
                signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
                not_before: issued_at,
                expires_at: key_expires_at,
                revoked_at: None,
                backup_hpke: RecoveryKeyAgreementEntry {
                    key_agreement_ref: backup_hpke_ref,
                    key_agreement_algorithm: RecoveryKeyAgreementAlgorithm::X25519,
                    public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
                    hpke_suites: vec![RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1],
                    r#use: RecoveryKeyAgreementUse::BackupHpke,
                    not_before: issued_at,
                    expires_at: key_expires_at,
                    revoked_at: None,
                },
            }],
        }],
        cooldown_seconds: None,
        issued_at,
        not_before: None,
        expires_at: None,
        auth_data: RecoveryPolicyAuthData {
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned()).map_err(
                |error| anyhow::anyhow!("recovery policy verification method is invalid: {error}"),
            )?,
            signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
            signature: arkret_sdk::Base64UrlString::new("AA".to_owned())
                .map_err(anyhow::Error::msg)?,
        },
        extra: Default::default(),
    };
    typed_policy.validate_shape()?;
    let bytes = recovery_policy_signing_payload(&typed_policy)?;
    let signature =
        sign_raw(&bytes).map_err(|err| anyhow::anyhow!("recovery policy sign: {err:?}"))?;
    typed_policy.auth_data.signature =
        arkret_sdk::Base64UrlString::new(B64.encode(signature)).map_err(anyhow::Error::msg)?;
    typed_policy.validate_shape()?;
    Ok(serde_json::to_value(typed_policy)?)
}

/// `key-management.md` §8.1 recovery-policy signature transcript.
/// `auth_data` is excluded as a whole; the signer identity and algorithm are
/// authorized by the accepted device context rather than self-authenticated by
/// the policy document.
fn recovery_policy_signing_payload(policy: &RecoveryPolicy) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(policy)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("recovery policy must serialize as an object"))?
        .remove("auth_data")
        .ok_or_else(|| anyhow::anyhow!("recovery policy auth_data is required"))?;
    let mut transcript = b"ak.identity.recovery_policy.signature.v1\n".to_vec();
    transcript.extend_from_slice(&arkret_sdk::canonical::canonical_json_bytes(&value)?);
    Ok(transcript)
}

fn principal_scoped_recovery_policy_verification_method<'a>(
    principal_did: &arkret_sdk::Did,
    signer: &'a crate::event_signer::InksonEventSigner,
) -> anyhow::Result<&'a str> {
    let verification_method = signer.verification_method().trim();
    principal_scoped_recovery_policy_verification_method_id(principal_did, verification_method)?;
    Ok(verification_method)
}

fn principal_scoped_recovery_policy_verification_method_id(
    principal_did: &arkret_sdk::Did,
    verification_method: &str,
) -> anyhow::Result<()> {
    if verification_method
        .strip_prefix(principal_did.as_str())
        .and_then(|rest| rest.strip_prefix('#'))
        .is_some_and(|fragment| !fragment.trim().is_empty())
    {
        return Ok(());
    }
    anyhow::bail!(
        "active signer verification_method `{}` is not scoped to principal_id `{}`; recovery policy requires a current accepted device signing key such as `{}`",
        verification_method,
        principal_did,
        format_args!("{principal_did}#<device_id>"),
    )
}

pub async fn ensure_active_recovery_policy(
    api: &TransportClient,
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    principal_control_realm_id: &arkret_sdk::RealmId,
    accepted_pcr_genesis_unit: &arkret_wire::PcrGenesisUnit,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<RecoveryPolicySummary> {
    let principal_core_id = arkret_sdk::project_did_to_core_id(principal_did)?;
    if principal_core_id != account_id.principal_id {
        anyhow::bail!("recovery policy principal projection does not match account authority");
    }
    if let Some(policy) = fetch_active_recovery_policy(api).await? {
        validate_active_policy_key_material(&policy, account_id, key_material)?;
        return Ok(policy);
    }

    let description = api.describe().await?;
    let body = build_signed_genesis_recovery_policy_for_session_device(
        principal_did,
        account_id,
        description.trust_domain.as_str(),
        device_id,
        key_material,
    )?;
    publish_recovery_policy(
        api,
        principal_did,
        account_id,
        device_id,
        principal_control_realm_id,
        accepted_pcr_genesis_unit,
        body,
    )
    .await?;

    let policy = fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server accepted recovery policy but did not expose it"))?;
    validate_active_policy_key_material(&policy, account_id, key_material)?;
    Ok(policy)
}

// The `expect` below asserts the delayed-submission lease invariant named in
// its message; a `?` rewrite would add an error path no caller can reach.
#[allow(clippy::expect_used)]
async fn publish_recovery_policy(
    api: &TransportClient,
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    _device_id: &arkret_sdk::DeviceId,
    principal_control_realm_id: &arkret_sdk::RealmId,
    _accepted_pcr_genesis_unit: &arkret_wire::PcrGenesisUnit,
    policy_value: Value,
) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
    if arkret_sdk::project_did_to_core_id(principal_did)? != account_id.principal_id {
        anyhow::bail!("recovery policy principal projection does not match account authority");
    }
    let policy: RecoveryPolicy = serde_json::from_value(policy_value)?;
    policy.validate_shape()?;
    let recovery_payload = arkret_sdk::RecoveryPolicySetPayload {
        policy_id: policy.policy_id.clone(),
        value: policy,
    };
    recovery_payload.validate_shape()?;
    let payload = arkret_sdk::PolicySetStatePayload {
        policy_id: recovery_payload.policy_id.clone(),
        value: arkret_sdk::PolicySetValue::Recovery(Box::new(recovery_payload.value)),
    };
    let event = crate::operation::TypedOperationBuilder::new_for_station::<
        arkret_sdk::event_spec::PolicySet,
    >(
        principal_control_realm_id.to_string(),
        account_id.principal_id.as_str(),
        account_id.station_id.clone(),
        payload,
    )
    .build_sdk_event("inkson-recovery-policy")?;
    let submitter = api.event_submitter()?;
    let authored = submitter.author_for_direct_submission(&event).await?;
    let submission = submitter
        .prepare_initial_submissions(std::slice::from_ref(&authored))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("recovery policy authoring produced no submission"))?;
    let request = arkret_sdk::RecoveryPolicyPublishRequest::new(submission)?;
    api.put_recovery_policy(request.submission()).await
}

fn validate_policy_key_material_at(
    summary: &RecoveryPolicySummary,
    account_id: &arkret_sdk::AccountId,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    valid_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<DidUrl> {
    if summary.account_id != *account_id {
        anyhow::bail!("active recovery policy account does not match requested account");
    }
    summary.validate_shape()?;
    let policy = summary.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "active recovery policy omitted its signed key configuration; refusing to pair it with supplied recovery material"
        )
    })?;
    policy.validate_shape()?;
    if policy.policy_id != summary.policy_id
        || policy.account_id != summary.account_id
        || policy.version != summary.version
        || policy.trust_domain != summary.trust_domain
        || policy.supersedes_id != summary.supersedes_id
        || policy.issued_at != summary.issued_at
        || policy.expires_at != summary.expires_at
        || policy.methods != summary.methods
    {
        anyhow::bail!("active recovery policy summary does not match its signed policy body");
    }
    if policy
        .not_before
        .is_some_and(|not_before| valid_at < not_before)
        || policy
            .expires_at
            .is_some_and(|expires_at| valid_at >= expires_at)
    {
        anyhow::bail!("active recovery policy is outside its validity interval");
    }

    let matches = policy
        .methods
        .iter()
        .filter_map(|method| match method {
            arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } => Some(keys.as_slice()),
            _ => None,
        })
        .flatten()
        .filter(|entry| {
            entry.revoked_at.is_none()
                && entry.not_before <= valid_at
                && entry.expires_at > valid_at
                && entry.signature_algorithm == RecoverySignatureAlgorithm::Ed25519
                && entry.backup_hpke.revoked_at.is_none()
                && entry.backup_hpke.not_before <= valid_at
                && entry.backup_hpke.expires_at > valid_at
                && entry.public_key_multibase == key_material.recovery_proof_public_key_multikey
                && entry.backup_hpke.public_key_multibase
                    == key_material.backup_hpke_public_key_multikey
                && entry
                    .backup_hpke
                    .hpke_suites
                    .contains(&RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
        })
        .collect::<Vec<_>>();
    let [proof_key] = matches.as_slice() else {
        anyhow::bail!(
            "supplied Recovery Key does not match one active recovery proof/backup recipient pair; use the staged recovery-key handoff workflow"
        );
    };
    Ok(proof_key.verification_method.clone())
}

fn validate_active_policy_key_material(
    summary: &RecoveryPolicySummary,
    account_id: &arkret_sdk::AccountId,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<DidUrl> {
    validate_policy_key_material_at(summary, account_id, key_material, chrono::Utc::now())
}

fn frozen_recovery_unlock_verification_method(
    session: &arkret_sdk::RecoverySession,
    policy: &RecoveryPolicySummary,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<DidUrl> {
    session.validate_shape()?;
    if session.state != arkret_sdk::RecoverySessionState::Pending {
        anyhow::bail!("recovery unlock proof requires a pending recovery session");
    }
    if session.expires_at <= chrono::Utc::now() {
        anyhow::bail!("recovery unlock proof requires an unexpired recovery session");
    }
    if session.account_id != policy.account_id
        || session.policy_id != policy.policy_id
        || session.policy_version != policy.version
        || session.trust_domain != policy.trust_domain
    {
        anyhow::bail!(
            "recovery session does not match the supplied frozen accepted policy/version"
        );
    }
    validate_policy_key_material_at(
        policy,
        &session.account_id,
        key_material,
        session.created_at,
    )
}

fn recovery_unlock_transcript(
    session: &arkret_sdk::RecoverySession,
    verification_method: DidUrl,
) -> anyhow::Result<GenericRecoveryTranscript> {
    let transcript = GenericRecoveryTranscript {
        schema: arkret_models_crypto::RECOVERY_PROOF_TRANSCRIPT_SCHEMA.to_owned(),
        kind: RecoveryProofKind::RecoveryUnlock,
        request_id: session.request_id.clone(),
        session_grant_id: session.session_grant_id.clone(),
        session_grant_cnf_jkt: session.session_grant_cnf_jkt.clone(),
        account_id: session.account_id.clone(),
        requesting_device_id: session.requesting_device_id.clone(),
        requesting_device_public_key_did: session.requesting_device_public_key_did.clone(),
        trust_domain: session.trust_domain.clone(),
        policy_id: session.policy_id.clone(),
        policy_version: session.policy_version,
        recovery_session_id: session.recovery_session_id.clone(),
        identity_model: session.identity_model,
        model_generation_ref: session.current_device_generation_ref,
        publication_authority_context_digest: session.publication_authority_context_digest.clone(),
        challenge: session.challenge.clone(),
        expires_at: session.expires_at,
        created_at: session.created_at,
        proof_body: RecoveryTranscriptProofBody::RecoveryUnlock(RecoveryUnlockProofBody {
            kind: RecoveryUnlockProofKind::RecoveryUnlock,
            challenge: session.challenge.clone(),
            verification_method,
            signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
        }),
    };
    transcript.validate_shape()?;
    Ok(transcript)
}

pub fn build_recovery_unlock_proof_from_words(
    session: &arkret_sdk::RecoverySession,
    policy: &RecoveryPolicySummary,
    recovery_words: &str,
) -> anyhow::Result<arkret_sdk::RecoverySessionProof> {
    let normalized = crate::recovery_crypto::normalize_recovery_key_input(recovery_words)
        .ok_or_else(|| anyhow::anyhow!("Recovery Key must contain exactly 24 valid words"))?;
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        &normalized,
        "",
        0,
    )?;
    let verification_method =
        frozen_recovery_unlock_verification_method(session, policy, &key_material)?;
    let transcript = recovery_unlock_transcript(session, verification_method.clone())?;
    let transcript_bytes = arkret_sdk::canonical::canonical_json_bytes(&transcript)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_material.recovery_proof_seed);
    let signature = signing_key.sign(&transcript_bytes);
    Ok(arkret_sdk::RecoverySessionProof::RecoveryUnlock(
        RecoveryUnlockProofBodyWithSignature {
            kind: RecoveryUnlockProofKind::RecoveryUnlock,
            challenge: session.challenge.clone(),
            verification_method,
            signature_algorithm: RecoverySignatureAlgorithm::Ed25519,
            signature: arkret_sdk::Base64UrlString::new(arkret_sdk::canonical::base64url_encode(
                signature.to_bytes(),
            ))
            .map_err(anyhow::Error::msg)?,
        },
    ))
}

pub async fn ensure_recovery_policy(
    api: &TransportClient,
    principal_did: &arkret_sdk::Did,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    principal_control_realm_id: &arkret_sdk::RealmId,
    accepted_pcr_genesis_unit: &arkret_wire::PcrGenesisUnit,
    recovery_key: &str,
) -> anyhow::Result<RecoveryPolicySummary> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    ensure_active_recovery_policy(
        api,
        principal_did,
        account_id,
        device_id,
        principal_control_realm_id,
        accepted_pcr_genesis_unit,
        &key_material,
    )
    .await
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as _;

    use super::*;

    fn committed_ref(
        event_id: &str,
        commit_seed: u8,
        realm_id: &arkret_sdk::RealmId,
        stream_position: u64,
    ) -> arkret_wire::CommittedEventRef {
        arkret_wire::CommittedEventRef {
            event_id: arkret_sdk::EventId::new(event_id).unwrap(),
            commit_id: arkret_sdk::RealmCommitId::from_digest([commit_seed; 32]),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position,
        }
    }

    fn recovery_unlock_fixture() -> (
        String,
        arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
        RecoveryPolicySummary,
        arkret_sdk::RecoverySession,
    ) {
        crate::operation::set_authoring_station_id(None);
        let principal_did =
            arkret_sdk::Did::new("did:webvh:z6mkfixture:principal.example".to_owned()).unwrap();
        let account_id = arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&principal_did).unwrap(),
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:onboarding-station.example".to_owned(),
            )
            .unwrap(),
        );
        let words = crate::recovery_crypto::format_recovery_key(&[7_u8; 32]);
        let key_material =
            arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
                &words, "", 0,
            )
            .unwrap();
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [9_u8; 32],
            principal_did.as_str(),
            format!("{principal_did}#founding-device"),
        );
        let policy: RecoveryPolicy = serde_json::from_value(
            build_signed_genesis_recovery_policy_with_signer(
                &principal_did,
                &account_id,
                "ak:trust_domain:test",
                &key_material,
                &signer,
            )
            .unwrap(),
        )
        .unwrap();
        let recovery_method = policy
            .methods
            .iter()
            .find_map(|method| match method {
                arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } => {
                    Some(keys[0].verification_method.clone())
                }
                _ => None,
            })
            .unwrap();
        let summary = RecoveryPolicySummary {
            policy_id: policy.policy_id.clone(),
            account_id: account_id.clone(),
            version: policy.version,
            acceptance_basis_ref: arkret_sdk::RealmCommitId::from_digest([6; 32]),
            recovery_policy_ref: Some(arkret_sdk::RecoveryPolicyRef {
                policy_id: policy.policy_id.clone(),
                policy_version: policy.version,
            }),
            trust_domain: policy.trust_domain.clone(),
            supersedes_id: policy.supersedes_id.clone(),
            issued_at: policy.issued_at,
            expires_at: policy.expires_at,
            accepted_at: Some(policy.issued_at),
            methods: policy.methods.clone(),
            policy: Some(policy.clone()),
        };
        let realm_id = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [7; 32],
        ));
        let commit_id = arkret_sdk::RealmCommitId::from_digest([8; 32]);
        let device_signing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let device_multikey = arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(
            device_signing_key.verifying_key().as_bytes(),
        );
        let created_at = policy.issued_at + chrono::Duration::seconds(1);
        // Exercise a whole-second expiry: chrono's generic JSON serializer
        // omits .000, whereas the wire contract requires millisecond precision.
        let expires_at = chrono::DateTime::from_timestamp(
            (chrono::Utc::now() + chrono::Duration::minutes(15)).timestamp(),
            0,
        )
        .unwrap();
        let session: arkret_sdk::RecoverySession = serde_json::from_value(serde_json::json!({
            "schema": "ak.schema.recovery_session.v1",
            "request_id": "ak:request:0198ff00-0000-7000-8000-00000000000b",
            "recovery_session_id": "ak:recovery_session:0198ff00-0000-7000-8000-00000000000c",
            "session_grant_id": arkret_wire::SessionGrantId::from_issuance_digest([4; 32]),
            "session_grant_cnf_jkt": arkret_sdk::canonical::base64url_encode([5; 32]),
            "account_id": account_id,
            "requesting_device_id": "ak:device:0198ff00-0000-7000-8000-00000000000a",
            "requesting_device_public_key_did": format!("did:key:{device_multikey}"),
            "trust_domain": policy.trust_domain,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "identity_model": "pcr_policy",
            "current_device_generation_ref": 3,
            "realm_stream_head": {
                "stream_ref": {"kind": "realm", "realm_id": realm_id},
                "stream_position": 12,
                "commit_id": commit_id,
            },
            "publication_authority_context": {
                "authority_commit_id": commit_id,
                "scope_ref": {"kind": "realm", "realm_id": realm_id},
                "authority_set_policy": {
                    "schema": "ak.schema.authority_set_policy.v1",
                    "authority_set_id": "ak.authority_set.principal_control.v1",
                    "policy_kind": "principal_control",
                    "scope_ref": {"kind": "realm", "realm_id": realm_id},
                    "source_commit_id": commit_id,
                    "authorization_rules": [{
                        "rule_id": "recovery_unlock",
                        "issuer_role": "identity_recovery",
                        "allowed_actions": ["ak.device.reanchor"],
                        "issuers": [{"verification_method": recovery_method}],
                        "threshold": 1,
                    }],
                },
                "allowed_actions": ["ak.device.reanchor"],
            },
            "publication_authority_context_digest": format!("sha256:{}", "ab".repeat(32)),
            "challenge": arkret_sdk::canonical::base64url_encode([2; 32]),
            "state": "pending",
            "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "created_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "updated_at": created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }))
        .unwrap();
        session.validate_shape().unwrap();
        (words, key_material, summary, session)
    }

    #[test]
    fn recovery_unlock_proof_uses_frozen_policy_method_and_single_signature() {
        let (words, key_material, policy, session) = recovery_unlock_fixture();
        let proof = build_recovery_unlock_proof_from_words(&session, &policy, &words).unwrap();
        let arkret_sdk::RecoverySessionProof::RecoveryUnlock(proof) = proof else {
            panic!("expected recovery_unlock proof");
        };
        let policy_method = policy
            .policy
            .as_ref()
            .unwrap()
            .methods
            .iter()
            .find_map(|method| match method {
                arkret_sdk::RecoveryMethod::RecoveryUnlock { keys } => {
                    Some(keys[0].verification_method.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(proof.verification_method, policy_method);
        let proof_value = serde_json::to_value(&proof).unwrap();
        assert!(
            !proof_value
                .as_object()
                .unwrap()
                .contains_key("recovery_secret_ref")
        );
        assert!(
            !proof_value
                .as_object()
                .unwrap()
                .contains_key("unlock_commitment")
        );

        let transcript = recovery_unlock_transcript(&session, proof.verification_method).unwrap();
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&transcript).unwrap();
        let signature = arkret_sdk::canonical::base64url_decode(proof.signature.as_str()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&key_material.recovery_proof_public_key)
            .unwrap()
            .verify(&bytes, &signature)
            .unwrap();
    }

    #[test]
    fn recovery_unlock_proof_rejects_non_frozen_policy_and_wrong_words() {
        let (words, _key_material, mut policy, session) = recovery_unlock_fixture();
        policy.version += 1;
        assert!(
            build_recovery_unlock_proof_from_words(&session, &policy, &words)
                .unwrap_err()
                .to_string()
                .contains("frozen accepted policy/version")
        );

        let (_words, _key_material, policy, session) = recovery_unlock_fixture();
        let wrong_words = crate::recovery_crypto::format_recovery_key(&[8_u8; 32]);
        assert!(
            build_recovery_unlock_proof_from_words(&session, &policy, &wrong_words)
                .unwrap_err()
                .to_string()
                .contains("does not match one active recovery proof")
        );
    }

    #[test]
    fn pcr_genesis_coordinates_require_exact_ordered_realm_positions() {
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP")
                .unwrap();
        let create_id =
            arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let authorize_id =
            arkret_sdk::EventId::new("ak:event:ASgi2U7PbVyNs4UpiQAoXKoHv84g07gpBvuddCGiMMG1")
                .unwrap();
        let commits = [
            committed_ref(create_id.as_str(), 1, &realm_id, 0),
            committed_ref(authorize_id.as_str(), 2, &realm_id, 1),
        ];

        validate_pcr_genesis_coordinates(&realm_id, &create_id, &authorize_id, &commits).unwrap();

        let mut wrong_position = commits.clone();
        wrong_position[1].stream_position = 2;
        assert!(
            validate_pcr_genesis_coordinates(
                &realm_id,
                &create_id,
                &authorize_id,
                &wrong_position,
            )
            .is_err()
        );

        let mut swapped = commits;
        swapped.swap(0, 1);
        assert!(
            validate_pcr_genesis_coordinates(&realm_id, &create_id, &authorize_id, &swapped)
                .is_err()
        );
    }

    #[test]
    fn genesis_policy_uses_explicit_account_station_and_only_recovery_key_method() {
        crate::operation::set_authoring_station_id(None);
        let principal_did =
            arkret_sdk::Did::new("did:webvh:z6mkfixture:principal.example".to_owned()).unwrap();
        let account_id = arkret_sdk::AccountId::new(
            arkret_sdk::project_did_to_core_id(&principal_did).unwrap(),
            arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:onboarding-station.example".to_owned(),
            )
            .unwrap(),
        );
        let key_material =
            arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
                &crate::recovery_crypto::format_recovery_key(&[7_u8; 32]),
                "",
                0,
            )
            .unwrap();
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [9_u8; 32],
            principal_did.as_str(),
            format!("{principal_did}#founding-device"),
        );

        let value = build_signed_genesis_recovery_policy_with_signer(
            &principal_did,
            &account_id,
            "ak:trust_domain:test",
            &key_material,
            &signer,
        )
        .unwrap();
        let policy: RecoveryPolicy = serde_json::from_value(value).unwrap();

        assert_eq!(policy.account_id, account_id);
        assert_eq!(policy.methods.len(), 1);
        assert!(matches!(
            policy.methods.first(),
            Some(arkret_sdk::RecoveryMethod::RecoveryUnlock { .. })
        ));
    }
}
