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
    RecoveryHpkeSuite, RecoveryKeyAgreementAlgorithm, RecoveryKeyAgreementEntry,
    RecoveryKeyAgreementUse, RecoveryKeyEntry, RecoveryKeySignatureAlgorithm, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicyRef, RecoveryPolicySummary, RecoveryProofKind,
    RecoveryPublicationAuthorizationRule, RecoverySessionCreateRequestBody,
    RecoverySessionProofSubmitRequestBody, UnsignedRecoveryPolicy, UnsignedRecoveryPolicyBody,
};
use arkret_sdk::{DeviceId, DidUrl, NonEmptyString, PolicyId, TrustDomainId};
use arkret_wire::{AuthoritySetIssuer, AuthoritySetIssuerRole, event_kind_str};
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
    pub recovery_public_key_secret_storage_backup_count: usize,
    pub local_recovery_key_fingerprint: Option<String>,
}

impl AccountRecoveryState {
    /// The recovery-material gate is satisfied by the accepted recovery
    /// policy. Identity-root generations are derived from the offline recovery
    /// secret and verified public DID history; there is no wire backup class
    /// for DID recovery.
    pub fn server_recovery_configured(&self) -> bool {
        self.active_policy.is_some()
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
    Satisfied,
    Blocked(FirstBackupGateBlockReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstBackupGateBlockReason {
    NoAcceptedPrincipalControlSeal,
    NoActiveRecoveryPolicy,
}

pub fn first_backup_gate_status_from_payloads(
    accepted_principal_control_seal: bool,
    recovery_policy_response: &Value,
) -> FirstBackupGateStatus {
    if !accepted_principal_control_seal {
        return FirstBackupGateStatus::Blocked(
            FirstBackupGateBlockReason::NoAcceptedPrincipalControlSeal,
        );
    }
    let Some(policy) = parse_active_recovery_policy(recovery_policy_response) else {
        return FirstBackupGateStatus::Blocked(FirstBackupGateBlockReason::NoActiveRecoveryPolicy);
    };
    let _ = policy;
    FirstBackupGateStatus::Satisfied
}

pub async fn submit_principal_bootstrap_seal(
    api: &TransportClient,
    seal: &arkret_sdk::Seal,
) -> anyhow::Result<()> {
    let outcome = api.sdk_http_client()?.events_submit_seal(seal).await?;
    if outcome.seal_id != seal.id
        || outcome.accepted_event_digests != seal.delta
        || outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched PCR bootstrap Seal outcome");
    }
    Ok(())
}

pub async fn verify_recovery_material_evidence(
    api: &TransportClient,
    evidence: &crate::state::RecoveryMaterialEvidence,
) -> anyhow::Result<()> {
    verify_recovery_authority_evidence(api, evidence).await?;
    let policy = serde_json::to_value(api.get_recovery_policy().await?)?;
    match first_backup_gate_status_from_payloads(true, &policy) {
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
    if evidence.pcr_genesis_unit.create().actor_id
        != arkret_sdk::project_full_id_to_core_id(&evidence.principal_id)?
        || evidence.pcr_genesis_unit.create().realm_id != evidence.principal_control_realm_id
        || evidence.pcr_genesis_unit.founding_authorize().realm_id
            != evidence.principal_control_realm_id
        || evidence.bootstrap_seal.realm_id != evidence.principal_control_realm_id
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
    if !evidence.bootstrap_seal.delta.contains(&create_digest)
        || !evidence.bootstrap_seal.delta.contains(&authorize_digest)
        || !evidence
            .bootstrap_seal
            .covered_event_digests
            .contains(&create_digest)
        || !evidence
            .bootstrap_seal
            .covered_event_digests
            .contains(&authorize_digest)
    {
        anyhow::bail!("durable bootstrap Seal does not cover the complete PCR genesis unit");
    }
    let http = api.sdk_http_client()?;
    let resolved = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: vec![create.event_id.clone(), authorize.event_id.clone()],
            event_digests: vec![create_digest, authorize_digest],
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
        })
        .await?;
    let resolved_seals = http
        .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
            realm_id: evidence.bootstrap_seal.realm_id.clone(),
            seal_refs: vec![evidence.bootstrap_seal.id.clone()],
            history_traversal_access: None,
        })
        .await?;
    if !resolved.events.iter().any(|event| event == create)
        || !resolved.events.iter().any(|event| event == authorize)
        || !resolved_seals
            .seals
            .iter()
            .any(|seal| seal == &evidence.bootstrap_seal)
    {
        anyhow::bail!("server no longer resolves the durable PCR bootstrap evidence exactly");
    }
    Ok(())
}

pub fn account_recovery_state_from_payloads(
    recovery_policy_response: &Value,
    backup_list_payload: &Value,
    local_recovery_key_fingerprint: Option<String>,
) -> AccountRecoveryState {
    let active_policy = parse_active_recovery_policy(recovery_policy_response);
    AccountRecoveryState {
        active_policy,
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
        principal_id: crate::mls_api_helpers::principal_core_id(principal_id)?,
        version: 1,
        supersedes: None,
        trust_domain: TrustDomainId::new(trust_domain.to_owned())?,
        allowed_proof_kinds: vec![
            RecoveryProofKind::PrincipalSigning,
            RecoveryProofKind::RecoveryUnlock,
        ],
        publication_authorization_rules: vec![
            RecoveryPublicationAuthorizationRule {
                rule_id: "principal_signing".to_owned(),
                proof_kind: RecoveryProofKind::PrincipalSigning,
                issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec![event_kind_str::DEVICE_REANCHOR.to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: principal_signing_ref,
                }],
                threshold: 1,
            },
            RecoveryPublicationAuthorizationRule {
                rule_id: "recovery_unlock".to_owned(),
                proof_kind: RecoveryProofKind::RecoveryUnlock,
                issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
                allowed_actions: vec![event_kind_str::DEVICE_REANCHOR.to_owned()],
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
    principal_control_realm_id: &arkret_sdk::RealmId,
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
    publish_recovery_policy(
        api,
        principal_id,
        device_id,
        principal_control_realm_id,
        body,
    )
    .await?;

    let policy = fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server accepted recovery policy but did not expose it"))?;
    validate_active_policy_key_material(&policy, principal_id, key_material)?;
    Ok(policy)
}

// The `expect` below asserts the delayed-submission lease invariant named in
// its message; a `?` rewrite would add an error path no caller can reach.
#[allow(clippy::expect_used)]
async fn publish_recovery_policy(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    principal_control_realm_id: &arkret_sdk::RealmId,
    policy_value: Value,
) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
    let principal_core_id = crate::mls_api_helpers::principal_core_id(principal_id)?;
    let policy: RecoveryPolicy = serde_json::from_value(policy_value)?;
    policy.validate()?;
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
        principal_control_realm_id.to_string(),
        principal_core_id.as_str(),
        payload,
    )
    .build_sdk_event("inkson-recovery-policy")?;
    let submitter = api.event_submitter()?;
    let event = submitter.author_for_direct_submission(&event).await?;
    let http = api.sdk_http_client()?;
    crate::authorization_lease::ensure_for_events(
        &http,
        std::slice::from_ref(event.event()),
        &[event.digest_suite()],
    )
    .await?;
    let submission =
        crate::authorization_lease::delayed_initial_submission(&http, &event, event.digest_suite())
            .await?;
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
                    submit_first_recovery_policy_seal(
                        api,
                        principal_core_id.as_str(),
                        device_id,
                        &event,
                    )
                    .await?;
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
        .events_frontier_realm_seal_head(policy_event.realm_id.as_str())
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
    let expected_digest = arkret_sdk::Hash::new(
        policy_event.event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?,
    )?;
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
    let requested_principal_core = crate::mls_api_helpers::principal_core_id(principal_id)?;
    if summary.principal_id != requested_principal_core {
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
    let recovery_secret_ref = validate_active_policy_key_material(
        policy,
        session.principal_authority.principal_id.as_str(),
        &key_material,
    )?;
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

pub async fn ensure_recovery_policy(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    principal_control_realm_id: &arkret_sdk::RealmId,
    recovery_key: &str,
) -> anyhow::Result<ActiveRecoveryPolicy> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    ensure_active_recovery_policy(
        api,
        principal_id,
        device_id,
        principal_control_realm_id,
        &key_material,
    )
    .await
}

/// Build the `recovery-session.schema.json` `create_request` body.
pub fn create_session_body(
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<RecoverySessionCreateRequestBody> {
    Ok(RecoverySessionCreateRequestBody {
        principal_authority: arkret_sdk::PrincipalAuthorityKey::new(
            crate::mls_api_helpers::principal_core_id(principal_id)?,
            crate::operation::authoring_principal_server_id()?,
        ),
        requesting_device_id: DeviceId::new(requesting_device_id.trim().to_owned())?,
        trust_domain: TrustDomainId::new(trust_domain.trim().to_owned())?,
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
