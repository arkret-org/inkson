//! 6.1 / 6.3 — recovery client orchestration.
//!
//! Pure request builders (unit-tested) + thin async wrappers over
//! [`crate::transport::TransportClient`] that drive the REC-1 recovery strand:
//!
//! - 6.1: fetch + parse the active recovery policy.
//! - 6.3: open a recovery session and sign + submit a `principal_signing` proof.
//!
//! Recovery completion is a durable protocol operation and is deliberately not
//! exposed here as a direct HTTP side effect.

use arkret_models_crypto::{
    KeyBackupContentItem, RecoveryHpkeSuite, RecoveryKeyAgreementAlgorithm,
    RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse, RecoveryKeyEntry,
    RecoveryKeySignatureAlgorithm, RecoveryPolicy, RecoveryPolicyActiveOutcome, RecoveryPolicyRef,
    RecoveryPolicySummary, RecoveryProofKind, RecoveryPublicationAuthorizationRule,
    RecoverySessionCreateRequestBody, RecoverySessionProofSubmitRequestBody,
    UnsignedRecoveryPolicy, UnsignedRecoveryPolicyBody,
};
use arkret_sdk::{DeviceId, Did, DidUrl, NonEmptyString, PolicyId, TypedTrustDomainId};
use arkret_wire::{AuthoritySetIssuer, AuthoritySetIssuerRole};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::transport::TransportClient;

/// 6.1 — parsed active recovery policy summary (the fields a client surfaces).
pub type ActiveRecoveryPolicy = RecoveryPolicySummary;

/// Account-level recovery state derived from server facts plus optional local
/// display metadata.
#[derive(Clone, Debug, Default)]
pub struct AccountRecoveryState {
    pub active_policy: Option<ActiveRecoveryPolicy>,
    pub accepted_did_recovery_first_backup_count: usize,
    pub recovery_public_key_secret_storage_backup_count: usize,
    pub local_recovery_key_fingerprint: Option<String>,
}

impl AccountRecoveryState {
    /// The account is recoverable only when the server has both the accepted
    /// policy and the DID recovery backup required by the first-backup gate.
    pub fn server_recovery_configured(&self) -> bool {
        self.active_policy.is_some() && self.accepted_did_recovery_first_backup_count > 0
    }

    /// Local fingerprints prove only that this browser once saw a recovery key.
    /// They do not prove that the account has a server-side recovery backup.
    pub fn local_only_recovery_key(&self) -> bool {
        self.local_recovery_key_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| !fingerprint.trim().is_empty())
            && !self.server_recovery_configured()
    }
}

/// Parse the `GET recovery-policy` response (`{ "active_policy": <summary|null> }`)
/// into [`ActiveRecoveryPolicy`]. Returns `None` when no policy is accepted.
pub fn parse_active_recovery_policy(response: &Value) -> Option<ActiveRecoveryPolicy> {
    let outcome = serde_json::from_value::<RecoveryPolicyActiveOutcome>(response.clone()).ok()?;
    let policy = outcome.active_policy?;
    if policy.version == 0 {
        return None;
    }
    Some(policy)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstBackupGateStatus {
    Satisfied { backup_id: String },
    Blocked(FirstBackupGateBlockReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstBackupGateBlockReason {
    NoActiveRecoveryPolicy,
    NoMatchingDidRecoveryBackup {
        policy_id: String,
        policy_version: u64,
    },
}

pub fn first_backup_gate_status_from_payloads(
    recovery_policy_response: &Value,
    backup_list_payload: &Value,
) -> FirstBackupGateStatus {
    let Some(policy) = parse_active_recovery_policy(recovery_policy_response) else {
        return FirstBackupGateStatus::Blocked(FirstBackupGateBlockReason::NoActiveRecoveryPolicy);
    };
    match matching_did_recovery_first_backup_id(backup_list_payload, &policy) {
        Some(backup_id) => FirstBackupGateStatus::Satisfied { backup_id },
        None => FirstBackupGateStatus::Blocked(
            FirstBackupGateBlockReason::NoMatchingDidRecoveryBackup {
                policy_id: policy.policy_id.as_str().to_owned(),
                policy_version: policy.version,
            },
        ),
    }
}

pub fn account_recovery_state_from_payloads(
    recovery_policy_response: &Value,
    backup_list_payload: &Value,
    local_recovery_key_fingerprint: Option<String>,
) -> AccountRecoveryState {
    let active_policy = parse_active_recovery_policy(recovery_policy_response);
    let accepted_did_recovery_first_backup_count = active_policy
        .as_ref()
        .map(|policy| count_matching_did_recovery_first_backups(backup_list_payload, policy))
        .unwrap_or(0);
    AccountRecoveryState {
        active_policy,
        accepted_did_recovery_first_backup_count,
        recovery_public_key_secret_storage_backup_count: count_backups_by_class_and_method(
            backup_list_payload,
            "secret_storage",
            "recovery_public_key",
        ),
        local_recovery_key_fingerprint: local_recovery_key_fingerprint
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
    }
}

fn count_backups_by_class_and_method(
    list_payload: &Value,
    backup_kind: &str,
    recipient_method: &str,
) -> usize {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| {
            backup.get("backup_kind").and_then(Value::as_str) == Some(backup_kind)
                && backup
                    .get("encryption")
                    .and_then(|encryption| encryption.get("recipient_method"))
                    .and_then(Value::as_str)
                    == Some(recipient_method)
        })
        .count()
}

fn count_matching_did_recovery_first_backups(
    list_payload: &Value,
    policy: &ActiveRecoveryPolicy,
) -> usize {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| did_recovery_backup_matches_active_policy(backup, policy))
        .count()
}

/// 6.1 — fetch + parse the active recovery policy.
pub async fn fetch_active_recovery_policy(
    api: &TransportClient,
) -> anyhow::Result<Option<ActiveRecoveryPolicy>> {
    // `parse_active_recovery_policy` reads `active_policy.*` leniently via
    // `Value` accessors; serialize the typed outcome back to its wire JSON.
    let response = serde_json::to_value(&api.get_recovery_policy().await?)?;
    Ok(parse_active_recovery_policy(&response))
}

pub fn build_signed_genesis_recovery_policy(
    principal_id: &str,
    trust_domain: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<Value> {
    if let Some(signer) = crate::event_signer::active_signer()
        && let Ok(verification_method) =
            principal_scoped_recovery_policy_verification_method(principal_id, &signer)
    {
        return build_signed_genesis_recovery_policy_with_raw_signer(
            principal_id,
            trust_domain,
            key_material,
            verification_method,
            |bytes| signer.sign_raw(bytes),
        );
    }

    anyhow::bail!(
        "active signer verification_method is not scoped to principal_id `{principal_id}`; \
         pass the current session device_id for genesis device signing"
    )
}

pub fn build_signed_genesis_recovery_policy_for_session_device(
    principal_id: &str,
    trust_domain: &str,
    device_id: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<Value> {
    let device_id = device_id.trim();
    if device_id.is_empty() {
        anyhow::bail!("device_id is required");
    }
    if let Some(signer) = crate::event_signer::active_signer() {
        if signer.device_id() != Some(device_id) {
            anyhow::bail!("active signer is not bound to current session device `{device_id}`");
        }
        let verification_method = format!("{principal_id}#{device_id}");
        return build_signed_genesis_recovery_policy_with_raw_signer(
            principal_id,
            trust_domain,
            key_material,
            &verification_method,
            |bytes| signer.sign_raw(bytes),
        );
    }

    let signer = default_principal_scoped_recovery_policy_signer(principal_id, device_id)?;
    build_signed_genesis_recovery_policy_with_signer(
        principal_id,
        trust_domain,
        key_material,
        &signer,
    )
}

fn default_principal_scoped_recovery_policy_signer(
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<crate::event_signer::InksonEventSigner> {
    let principal_id = principal_id.trim();
    if principal_id.is_empty() {
        anyhow::bail!("principal_id is required");
    }
    let device_id = device_id.trim();
    if device_id.is_empty() {
        anyhow::bail!("device_id is required");
    }
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    let material = crate::secure_key_store::ensure_signing_seed(store.as_ref())
        .map_err(|err| anyhow::anyhow!("ensure recovery policy signing seed failed: {err}"))?;
    Ok(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            material.seed,
            principal_id,
            format!("{principal_id}#{device_id}"),
        ),
    )
}

fn build_signed_genesis_recovery_policy_with_signer(
    principal_id: &str,
    trust_domain: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<Value> {
    let verification_method =
        principal_scoped_recovery_policy_verification_method(principal_id, signer)?;
    build_signed_genesis_recovery_policy_with_raw_signer(
        principal_id,
        trust_domain,
        key_material,
        verification_method,
        |bytes| signer.sign_raw(bytes),
    )
}

fn build_signed_genesis_recovery_policy_with_raw_signer(
    principal_id: &str,
    trust_domain: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    verification_method: &str,
    sign_raw: impl Fn(&[u8]) -> Result<Vec<u8>, crate::event_signer::EventSignerError>,
) -> anyhow::Result<Value> {
    let principal_id = principal_id.trim();
    let trust_domain = trust_domain.trim();
    let verification_method = verification_method.trim();
    if principal_id.is_empty() {
        anyhow::bail!("principal_id is required");
    }
    if trust_domain.is_empty() {
        anyhow::bail!("trust_domain is required");
    }
    principal_scoped_recovery_policy_verification_method_id(principal_id, verification_method)?;
    let issued_at = chrono::Utc::now();
    let key_expires_at = issued_at + chrono::Duration::days(3650);
    let recovery_proof_ref = DidUrl::new(format!("{principal_id}#recovery-proof-0"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let backup_hpke_ref = DidUrl::new(format!("{principal_id}#backup-hpke-0"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let principal_signing_ref =
        DidUrl::new(verification_method.to_owned()).map_err(|error| anyhow::anyhow!(error))?;
    let policy_body = UnsignedRecoveryPolicyBody {
        policy_id: PolicyId::new(format!("ak:policy:{}", crate::operation::uuid_v7()))?,
        principal_id: Did::new(principal_id.to_owned())?,
        version: 1,
        supersedes: None,
        trust_domain: TypedTrustDomainId::new(trust_domain.to_owned())?,
        allowed_proof_kinds: vec![
            RecoveryProofKind::PrincipalSigning,
            RecoveryProofKind::RecoveryUnlock,
        ],
        publication_authorization_rules: vec![
            RecoveryPublicationAuthorizationRule {
                rule_id: "principal_signing".to_owned(),
                proof_kind: RecoveryProofKind::PrincipalSigning,
                issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec!["ak.device.reanchor".to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: principal_signing_ref,
                }],
                threshold: 1,
            },
            RecoveryPublicationAuthorizationRule {
                rule_id: "recovery_unlock".to_owned(),
                proof_kind: RecoveryProofKind::RecoveryUnlock,
                issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec!["ak.device.reanchor".to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: recovery_proof_ref.clone(),
                }],
                threshold: 1,
            },
        ],
        threshold: None,
        device_quorum: None,
        trusted_recovery_services: None,
        recovery_keys: Some(vec![RecoveryKeyEntry {
            verification_method: recovery_proof_ref,
            public_key_multibase: NonEmptyString::new(
                key_material.recovery_proof_public_key_multikey.clone(),
            )
            .map_err(|error| anyhow::anyhow!(error))?,
            key_agreement_ref: backup_hpke_ref.clone(),
            signature_algorithm: RecoveryKeySignatureAlgorithm::Ed25519,
            not_before: issued_at,
            expires_at: key_expires_at,
            revoked_at: None,
        }]),
        recovery_key_agreements: Some(vec![RecoveryKeyAgreementEntry {
            key_agreement_ref: backup_hpke_ref,
            key_agreement_algorithm: RecoveryKeyAgreementAlgorithm::X25519,
            public_key_multibase: NonEmptyString::new(
                key_material.backup_hpke_public_key_multikey.clone(),
            )
            .map_err(|error| anyhow::anyhow!(error))?,
            hpke_suites: vec![RecoveryHpkeSuite::X25519ChaCha20Poly1305],
            usage: RecoveryKeyAgreementUse::BackupHpke,
            not_before: issued_at,
            expires_at: key_expires_at,
            revoked_at: None,
        }]),
        approval_requirement: None,
        audit: None,
        issued_at,
        not_before: None,
        expires_at: None,
        extra: Default::default(),
    };
    let unsigned = UnsignedRecoveryPolicy::new(
        policy_body,
        arkret_sdk::DidUrl::new(verification_method.to_owned()).map_err(|error| {
            anyhow::anyhow!("recovery policy verification method is invalid: {error}")
        })?,
        arkret_sdk::KeyBackupSignatureAlgorithm::Ed25519,
    )?;
    let bytes = unsigned.signing_payload_bytes()?;
    let signature =
        sign_raw(&bytes).map_err(|err| anyhow::anyhow!("recovery policy sign: {err:?}"))?;
    let typed_policy = unsigned.attach_signature(
        arkret_sdk::Base64UrlString::new(B64.encode(signature)).map_err(anyhow::Error::msg)?,
    )?;
    typed_policy.validate()?;
    Ok(serde_json::to_value(typed_policy)?)
}

fn principal_scoped_recovery_policy_verification_method<'a>(
    principal_id: &str,
    signer: &'a crate::event_signer::InksonEventSigner,
) -> anyhow::Result<&'a str> {
    let verification_method = signer.verification_method().trim();
    principal_scoped_recovery_policy_verification_method_id(principal_id, verification_method)?;
    Ok(verification_method)
}

fn principal_scoped_recovery_policy_verification_method_id(
    principal_id: &str,
    verification_method: &str,
) -> anyhow::Result<()> {
    if verification_method
        .strip_prefix(principal_id)
        .and_then(|rest| rest.strip_prefix('#'))
        .is_some_and(|fragment| !fragment.trim().is_empty())
    {
        return Ok(());
    }
    anyhow::bail!(
        "active signer verification_method `{}` is not scoped to principal_id `{}`; recovery policy requires a principal signing key such as `{}`",
        verification_method,
        principal_id,
        format_args!("{principal_id}#<device_id>"),
    )
}

pub async fn ensure_active_recovery_policy(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<ActiveRecoveryPolicy> {
    if let Some(policy) = fetch_active_recovery_policy(api).await? {
        validate_active_policy_key_material(&policy, principal_id, key_material)?;
        return Ok(policy);
    }

    // DIAG (describe-storm): this describe fires only when no active recovery
    // policy exists yet. If it repeats, a caller is re-running recovery-policy
    // establishment in a loop (fetch=None -> describe -> put -> still None).
    // Remove once the driver is fixed.
    tracing::warn!(target: "recovery_diag", %principal_id, "ensure_active_recovery_policy: no policy -> describe + put");
    let description = api.describe().await?;
    let body = build_signed_genesis_recovery_policy_for_session_device(
        principal_id,
        description.trust_domain.as_str(),
        device_id,
        key_material,
    )?;
    publish_recovery_policy(api, principal_id, device_id, body).await?;

    let policy = fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server accepted recovery policy but did not expose it"))?;
    validate_active_policy_key_material(&policy, principal_id, key_material)?;
    Ok(policy)
}

async fn publish_recovery_policy(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    policy_value: Value,
) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
    let policy: RecoveryPolicy = serde_json::from_value(policy_value)?;
    policy.validate()?;
    let principal = arkret_sdk::Did::new(principal_id.to_owned())?;
    let realm_id = arkret_sdk::principal_control_realm_id(&principal);
    let recovery_payload = arkret_sdk::RecoveryPolicySetPayload {
        policy_id: policy.policy_id.clone(),
        value: policy,
    };
    recovery_payload.validate()?;
    let payload = arkret_sdk::PolicySetStatePayload {
        policy_id: arkret_sdk::NonEmptyString::new(recovery_payload.policy_id.as_str().to_owned())
            .map_err(anyhow::Error::msg)?,
        value: Some(serde_json::to_value(recovery_payload.value)?),
        state: None,
        reason: None,
    };
    let event = crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::PolicySet>(
        realm_id,
        principal_id,
        payload,
    )
    .build_sdk_event("inkson-recovery-policy")?;
    let submitter = api.event_submitter()?;
    let (event, _) = submitter.prepare_sdk_event_for_submit(&event).await?;
    let http = api.sdk_http_client()?;
    crate::authorization_lease::ensure_for_events(&http, std::slice::from_ref(&event)).await?;
    let submission = crate::authorization_lease::delayed_initial_submission(&http, &event).await?;
    let request = arkret_sdk::RecoveryPolicyPublishRequest {
        event: submission.event,
        authorization_lease: submission
            .authorization_lease
            .expect("recovery policy publication uses an explicit authorization lease"),
        cba_proof_bundles: submission.cba_proof_bundles,
        control_proposal_ack: submission.control_proposal_ack,
    };

    // A self-PCR notary is the principal's current device, never the hosting
    // service. The first typed publication accepts the Event and returns
    // frontier_unavailable; the client must then publish the device-signed
    // successor Seal before retrying the identical request.
    const FRONTIER_RETRY_ATTEMPTS: usize = 120;
    let mut successor_seal_submitted = false;
    for attempt in 0..FRONTIER_RETRY_ATTEMPTS {
        match api.put_recovery_policy(&request).await {
            Ok(outcome) => return Ok(outcome),
            Err(error)
                if recovery_policy_frontier_pending(&error)
                    && attempt + 1 < FRONTIER_RETRY_ATTEMPTS =>
            {
                if !successor_seal_submitted {
                    submit_first_recovery_policy_seal(api, principal_id, device_id, &event).await?;
                    successor_seal_submitted = true;
                }
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded recovery policy retry loop always returns")
}

async fn submit_first_recovery_policy_seal(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    policy_event: &arkret_sdk::Event,
) -> anyhow::Result<()> {
    let http = api.sdk_http_client()?;
    let events = http
        .events_read_all_pages(policy_event.realm_id.as_str())
        .await?;
    let complete_events = crate::models::require_complete_event_rows(
        &events.events,
        "recovery policy successor Seal construction",
    )?;
    let create = complete_events
        .iter()
        .find(|event| {
            event.kind == arkret_sdk::EventKind::RealmCreate
                && event.actor_id.as_str() == principal_id
        })
        .ok_or_else(|| anyhow::anyhow!("self-PCR history omitted its bootstrap create Event"))?;
    let authorize = complete_events
        .iter()
        .find(|event| {
            event.kind == arkret_sdk::EventKind::DeviceAuthorize
                && event.actor_id.as_str() == principal_id
                && event.actor_seq == 1
        })
        .ok_or_else(|| anyhow::anyhow!("self-PCR history omitted its bootstrap authorize Event"))?;
    let predecessor = api
        .event_submitter()?
        .events_frontier_realm_seal_view(policy_event.realm_id.as_str())
        .await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
    if signer.device_id() != Some(device_id) {
        anyhow::bail!("active device signer does not match the recovery-policy device");
    }
    let hlc = crate::signing_stamp::issue_protocol_hlc(
        principal_id,
        device_id,
        policy_event.realm_id.as_str(),
    )?;
    let seal = signer
        .sign_self_principal_first_successor_seal(
            create,
            authorize,
            policy_event,
            &predecessor,
            hlc,
        )
        .map_err(|error| anyhow::anyhow!("sign recovery-policy successor Seal: {error}"))?;
    let expected_id = seal.id.clone();
    let expected_digest = arkret_sdk::Hash::new(policy_event.event_digest()?)?;
    let expected_state_root = seal.state_root.clone();
    let outcome = http.events_submit_seal(&seal).await?;
    if outcome.seal_id != expected_id
        || outcome.accepted_event_digests != vec![expected_digest]
        || outcome.post_state_root != expected_state_root
    {
        anyhow::bail!("Principal Server returned a mismatched recovery-policy Seal outcome");
    }
    Ok(())
}

fn recovery_policy_frontier_pending(error: &anyhow::Error) -> bool {
    crate::api_error::api_error_status_and_envelope(error)
        .is_some_and(|(_, envelope)| envelope.code() == "frontier_unavailable")
}

fn validate_active_policy_key_material(
    summary: &ActiveRecoveryPolicy,
    principal_id: &str,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<DidUrl> {
    if summary.principal_id.as_str() != principal_id.trim() {
        anyhow::bail!(
            "active recovery policy principal `{}` does not match requested principal `{}`",
            summary.principal_id,
            principal_id.trim()
        );
    }
    let policy = summary.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "active recovery policy omitted its signed key configuration; refusing to pair it with supplied recovery material"
        )
    })?;
    policy.validate()?;
    if policy.policy_id != summary.policy_id
        || policy.principal_id != summary.principal_id
        || policy.version != summary.version
    {
        anyhow::bail!("active recovery policy summary does not match its signed policy body");
    }

    let agreement_ref = policy
        .recovery_key_agreements
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|entry| {
            entry.public_key_multibase.as_str() == key_material.backup_hpke_public_key_multikey
        })
        .map(|entry| &entry.key_agreement_ref);
    let Some(agreement_ref) = agreement_ref else {
        anyhow::bail!(
            "supplied Recovery Key does not match the active policy backup recipient; use the staged recovery-key handoff workflow"
        );
    };
    let proof_key = policy
        .recovery_keys
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|entry| {
            &entry.key_agreement_ref == agreement_ref
                && entry.public_key_multibase.as_str()
                    == key_material.recovery_proof_public_key_multikey
        });
    let Some(proof_key) = proof_key else {
        anyhow::bail!(
            "supplied Recovery Key does not match the active policy recovery proof key; use the staged recovery-key handoff workflow"
        );
    };
    Ok(proof_key.verification_method.clone())
}

pub fn build_recovery_unlock_proof_from_words(
    session: &arkret_sdk::RecoverySessionState,
    policy: &ActiveRecoveryPolicy,
    recovery_words: &str,
) -> anyhow::Result<arkret_sdk::RecoverySessionProof> {
    let normalized = crate::recovery_crypto::normalize_recovery_key_input(recovery_words)
        .ok_or_else(|| anyhow::anyhow!("Recovery Key must contain exactly 24 valid words"))?;
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        &normalized,
        "",
        0,
    )?;
    let recovery_secret_ref =
        validate_active_policy_key_material(policy, session.principal_id.as_str(), &key_material)?;
    arkret_sdk::identity_root::build_recovery_unlock_proof(
        session,
        recovery_secret_ref.as_str(),
        &key_material,
    )
    .map_err(anyhow::Error::from)
}

pub async fn submit_recovery_unlock_proof(
    api: &TransportClient,
    session: &arkret_sdk::RecoverySessionState,
    policy: &ActiveRecoveryPolicy,
    recovery_words: &str,
) -> anyhow::Result<arkret_sdk::RecoverySessionProofSubmitOutcome> {
    let proof = build_recovery_unlock_proof_from_words(session, policy, recovery_words)?;
    api.submit_recovery_proof(
        session.recovery_session_id.as_str(),
        &RecoverySessionProofSubmitRequestBody { proof },
    )
    .await
}

pub async fn ensure_recovery_policy_and_did_recovery_backup(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    recovery_key: &str,
) -> anyhow::Result<String> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device signer is required"))?;
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    let policy = ensure_active_recovery_policy(api, principal_id, device_id, &key_material).await?;
    // `matching_did_recovery_first_backup_id` reads `backups[]` leniently via
    // `Value` accessors; serialize the typed list back to its wire JSON.
    let list = serde_json::to_value(
        &api.list_key_backups_by_series(None, Some("did_recovery"))
            .await?,
    )?;
    if let Some(backup_id) = matching_did_recovery_first_backup_id(&list, &policy) {
        return Ok(backup_id);
    }

    let backup_id = format!("ak:backup:{}", crate::operation::uuid_v7());
    let recovery_key_ref = format!("{}#backup-hpke-0", principal_id.trim());
    let created_at = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
    #[derive(serde::Serialize)]
    struct RecoveryPolicyBinding<'a> {
        policy_id: &'a str,
        policy_version: u64,
    }

    #[derive(serde::Serialize)]
    struct DidRecoveryMetadata<'a> {
        schema: &'static str,
        principal_id: &'a str,
        root_generation: u64,
        root_public_key_multibase: &'a str,
        next_root_public_key_multibase: &'a str,
        next_root_key_hash: &'a str,
        recovery_policy_ref: RecoveryPolicyBinding<'a>,
        created_at: &'a str,
    }

    let plaintext = crate::canonical::canonical_json_bytes(&DidRecoveryMetadata {
        schema: "ak.local.did_recovery_metadata.v1",
        principal_id,
        root_generation: key_material.root_generation,
        root_public_key_multibase: &key_material.root_public_key_multikey,
        next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
        next_root_key_hash: &key_material.next_root_key_hash,
        recovery_policy_ref: RecoveryPolicyBinding {
            policy_id: policy.policy_id.as_str(),
            policy_version: policy.version,
        },
        created_at: &created_at,
    })?;
    let body = crate::key_backup::build_did_recovery_backup_body(
        &backup_id,
        principal_id,
        device_id,
        &key_material.backup_hpke_public_key,
        &recovery_key_ref,
        &plaintext,
        policy.policy_id.as_str(),
        policy.version,
    )?;
    api.put_key_backup(&backup_id, body, &signer).await?;
    Ok(backup_id)
}

pub fn matching_did_recovery_first_backup_id(
    list_payload: &Value,
    policy: &ActiveRecoveryPolicy,
) -> Option<String> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|backup| {
            if !did_recovery_backup_matches_active_policy(backup, policy) {
                return None;
            }
            backup
                .get("backup_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|backup_id| !backup_id.is_empty())
                .map(str::to_owned)
        })
        .next()
}

fn did_recovery_backup_matches_active_policy(
    backup: &Value,
    policy: &ActiveRecoveryPolicy,
) -> bool {
    backup.get("backup_kind").and_then(Value::as_str) == Some("did_recovery")
        && backup
            .get("encryption")
            .and_then(|encryption| encryption.get("recipient_method"))
            .and_then(Value::as_str)
            == Some("recovery_public_key")
        && backup
            .get("recovery_policy_ref")
            .and_then(|policy_ref| policy_ref.get("policy_id"))
            .and_then(Value::as_str)
            == Some(policy.policy_id.as_str())
        && backup
            .get("recovery_policy_ref")
            .and_then(|policy_ref| policy_ref.get("policy_version"))
            .and_then(Value::as_u64)
            == Some(policy.version)
        && backup_series_seq_is_first_when_present(backup)
}

fn backup_series_seq_is_first_when_present(backup: &Value) -> bool {
    match backup.get("series_seq") {
        Some(value) => value.as_u64() == Some(0),
        None => true,
    }
}

/// Build the `recovery-session.schema.json` `create_request` body.
pub fn create_session_body(
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<RecoverySessionCreateRequestBody> {
    Ok(RecoverySessionCreateRequestBody {
        principal_id: Did::new(principal_id.trim().to_owned())?,
        requesting_device_id: DeviceId::new(requesting_device_id.trim().to_owned())?,
        trust_domain: TypedTrustDomainId::new(trust_domain.trim().to_owned())?,
        expected_recovery_policy_ref: match expected_recovery_policy_ref {
            Some((policy_id, policy_version)) => Some(RecoveryPolicyRef {
                policy_id: PolicyId::new(policy_id.trim().to_owned())?,
                policy_version,
            }),
            None => None,
        },
    })
}

/// 6.3 — open a recovery session. Returns the session JSON (carries the
/// challenge + every binding field the proof transcript needs).
pub async fn open_recovery_session(
    api: &TransportClient,
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<Value> {
    let body = create_session_body(
        principal_id,
        requesting_device_id,
        trust_domain,
        expected_recovery_policy_ref,
    )?;
    // Callers read `recovery_session_id` from the session via lenient `Value`
    // accessors; serialize the typed session state back to its wire JSON.
    Ok(serde_json::to_value(
        &api.create_recovery_session(&body).await?,
    )?)
}

/// 6.3 — sign a `principal_signing` proof for `session` (with the principal
/// control key) and submit it. Returns the `proof_submit_response`.
pub async fn submit_principal_signing_proof(
    api: &TransportClient,
    session: &Value,
    verification_method: &str,
    identity_root_signing_key: &SigningKey,
) -> anyhow::Result<Value> {
    let proof = crate::recovery_proof::build_principal_signing_proof(
        session,
        verification_method,
        identity_root_signing_key,
    )?;
    let session_id = session
        .get("recovery_session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("session missing recovery_session_id"))?;
    let body = RecoverySessionProofSubmitRequestBody { proof };
    Ok(serde_json::to_value(
        &api.submit_recovery_proof(session_id, &body).await?,
    )?)
}
