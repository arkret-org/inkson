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
    RecoveryHpkeSuite, RecoveryKeyAgreementAlgorithm, RecoveryKeyAgreementEntry,
    RecoveryKeyAgreementUse, RecoveryKeyEntry, RecoveryKeySignatureAlgorithm, RecoveryPolicy,
    RecoveryPolicyActiveOutcome, RecoveryPolicySummary, UnsignedRecoveryPolicy,
    UnsignedRecoveryPolicyBody,
};
use arkret_sdk::{DidUrl, NonEmptyString, PolicyId, TrustDomainId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
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
    NoAcceptedPrincipalControlSeal,
    NoActiveRecoveryPolicy,
}

pub fn first_backup_gate_status(
    accepted_principal_control_seal: bool,
    recovery_policy_outcome: &RecoveryPolicyActiveOutcome,
) -> FirstBackupGateStatus {
    if !accepted_principal_control_seal {
        return FirstBackupGateStatus::Blocked(
            FirstBackupGateBlockReason::NoAcceptedPrincipalControlSeal,
        );
    }
    let Some(policy) = active_recovery_policy(recovery_policy_outcome) else {
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
        anyhow::bail!("Station returned a mismatched PCR bootstrap Seal outcome");
    }
    Ok(())
}

/// Refresh the Account Station's accepted PCR frontier after bootstrap submission.
/// The exact bootstrap bytes are checked through the existing accepted Seal lookup;
/// subsequent authoring consumes the Station's current digest suite and complete basis.
pub async fn refresh_principal_bootstrap_frontier(
    api: &TransportClient,
    state_store: &crate::runtime::input::StateStoreHandle,
    bootstrap_seal: &arkret_sdk::Seal,
) -> anyhow::Result<()> {
    let http = api.sdk_http_client()?;
    let accepted = http
        .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
            realm_id: bootstrap_seal.realm_id.clone(),
            selection: arkret_sdk::SealResolveSelection::SealRefs {
                seal_refs: vec![bootstrap_seal.id.clone()],
            },
            history_traversal_access: None,
        })
        .await?;
    let accepted = accepted.into_seals()?;
    anyhow::ensure!(
        accepted.as_slice() == [bootstrap_seal.clone()],
        "Station has not accepted the exact PCR bootstrap Seal"
    );
    crate::mls::governance_proof::refresh_realm_frontier_with_http(
        &http,
        state_store.clone(),
        bootstrap_seal.realm_id.as_str(),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    Ok(())
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
    let resolved_create = http.committed_event_get(&create.event_id).await?;
    let resolved_authorize = http.committed_event_get(&authorize.event_id).await?;
    let resolved_seals = http
        .seals_resolve(&arkret_sdk::SelfSealResolveRequestBody {
            realm_id: evidence.bootstrap_seal.realm_id.clone(),
            selection: arkret_sdk::SealResolveSelection::SealRefs {
                seal_refs: vec![evidence.bootstrap_seal.id.clone()],
            },
            history_traversal_access: None,
        })
        .await?;
    let resolved_seals = resolved_seals.into_seals()?;
    if !resolved_create
        .reducer_input()
        .is_some_and(|event| accepted_event_matches_genesis_basis(event, create, &create_digest))
        || !resolved_authorize.reducer_input().is_some_and(|event| {
            accepted_event_matches_genesis_basis(event, authorize, &authorize_digest)
        })
        || !resolved_seals
            .iter()
            .any(|seal| seal == &evidence.bootstrap_seal)
    {
        anyhow::bail!("server no longer resolves the durable PCR bootstrap evidence exactly");
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
    let policy_body = UnsignedRecoveryPolicyBody {
        policy_id: PolicyId::new(format!("ak:policy:{}", crate::operation::uuid_v7()))?,
        account_id: account_id.clone(),
        version: 1,
        supersedes_id: None,
        trust_domain: TrustDomainId::new(trust_domain.to_owned())?,
        methods: vec![arkret_sdk::RecoveryMethod::RecoveryUnlock {
            keys: vec![RecoveryKeyEntry {
                verification_method: recovery_proof_ref,
                public_key_multibase: NonEmptyString::new(
                    key_material.recovery_proof_public_key_multikey.clone(),
                )
                .map_err(anyhow::Error::msg)?,
                signature_algorithm: RecoveryKeySignatureAlgorithm::Ed25519,
                not_before: issued_at,
                expires_at: key_expires_at,
                revoked_at: None,
                backup_hpke: RecoveryKeyAgreementEntry {
                    key_agreement_ref: backup_hpke_ref,
                    key_agreement_algorithm: RecoveryKeyAgreementAlgorithm::X25519,
                    public_key_multibase: NonEmptyString::new(
                        key_material.backup_hpke_public_key_multikey.clone(),
                    )
                    .map_err(anyhow::Error::msg)?,
                    hpke_suites: vec![RecoveryHpkeSuite::X25519ChaCha20Poly1305],
                    usage: RecoveryKeyAgreementUse::BackupHpke,
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
    device_id: &arkret_sdk::DeviceId,
    principal_control_realm_id: &arkret_sdk::RealmId,
    accepted_pcr_genesis_unit: &arkret_wire::PcrGenesisUnit,
    policy_value: Value,
) -> anyhow::Result<arkret_sdk::RecoveryPolicyPublishOutcome> {
    let principal_core_id = arkret_sdk::project_did_to_core_id(principal_did)?;
    if principal_core_id != account_id.principal_id {
        anyhow::bail!("recovery policy principal projection does not match account authority");
    }
    let policy: RecoveryPolicy = serde_json::from_value(policy_value)?;
    policy.validate()?;
    let recovery_payload = arkret_sdk::RecoveryPolicySetPayload {
        policy_id: policy.policy_id.clone(),
        value: policy,
    };
    recovery_payload.validate()?;
    let payload = arkret_sdk::PolicySetStatePayload {
        policy_id: recovery_payload.policy_id,
        value: arkret_sdk::PolicyDocument::RecoveryPolicy(Box::new(recovery_payload.value)),
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
    let event = submitter.author_for_direct_submission(&event).await?;
    let http = api.sdk_http_client()?;
    crate::authorization_lease::ensure_for_events(
        &http,
        std::slice::from_ref(event.event()),
        &[event.digest_suite()],
    )
    .await?;
    let submission =
        crate::authorization_lease::delayed_authority_authored_self_principal_submission(
            &event,
            event.digest_suite(),
            accepted_pcr_genesis_unit.create(),
        )?;
    let request = arkret_sdk::RecoveryPolicyPublishRequest {
        event: submission.event,
        authorization_lease: submission
            .authorization_lease
            .expect("recovery policy publication uses an explicit authorization lease"),
        cbs_proof_bundles: submission.cbs_proof_bundles,
        control_proposal_ack: submission.control_proposal_ack,
    };

    // A self-PCR notary is the principal's current device, never the hosting
    // service. The first typed publication accepts the Event and returns
    // frontier_unavailable; the client must then publish the device-signed
    // successor Seal before retrying the identical request.
    const FRONTIER_RETRY_ATTEMPTS: usize = 120;
    let mut successor_seal_submitted = false;
    for attempt in 0..FRONTIER_RETRY_ATTEMPTS {
        match api
            .put_recovery_policy(&request, event.digest_suite())
            .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(error)
                if recovery_policy_frontier_pending(&error)
                    && attempt + 1 < FRONTIER_RETRY_ATTEMPTS =>
            {
                if !successor_seal_submitted {
                    submit_recovery_policy_seal(
                        api,
                        &principal_core_id,
                        device_id,
                        accepted_pcr_genesis_unit,
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

async fn submit_recovery_policy_seal(
    api: &TransportClient,
    principal_id: &arkret_sdk::DidCoreId,
    device_id: &arkret_sdk::DeviceId,
    accepted_pcr_genesis_unit: &arkret_wire::PcrGenesisUnit,
    policy_event: &arkret_sdk::Event,
) -> anyhow::Result<()> {
    let http = api.sdk_http_client()?;
    let create = accepted_pcr_genesis_unit.create();
    let authorize = accepted_pcr_genesis_unit.founding_authorize();
    if create.actor_id.signing_principal_id() != principal_id
        || authorize.actor_id.signing_principal_id() != principal_id
        || create.realm_id != policy_event.realm_id
        || authorize.realm_id != policy_event.realm_id
    {
        anyhow::bail!("accepted PCR genesis unit does not match the recovery-policy Event");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
    if signer.device_id() != Some(device_id.as_str()) {
        anyhow::bail!("active device signer does not match the recovery-policy device");
    }
    // Other legitimate PCR operations, such as invite consent, can already
    // precede the first recovery policy. Reproduce the actual accepted
    // history instead of assuming this policy occupies actor_seq=2.
    let context = crate::transport::prepare_principal_successor_seal(&http, policy_event).await?;
    crate::transport::submit_principal_successor_seal(&http, context, policy_event).await
}

fn recovery_policy_frontier_pending(error: &anyhow::Error) -> bool {
    crate::api_error::is_recovery_policy_frontier_pending_error(error)
}

fn validate_active_policy_key_material(
    summary: &RecoveryPolicySummary,
    account_id: &arkret_sdk::AccountId,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<DidUrl> {
    if summary.account_id != *account_id {
        anyhow::bail!("active recovery policy account does not match requested account");
    }
    let policy = summary.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "active recovery policy omitted its signed key configuration; refusing to pair it with supplied recovery material"
        )
    })?;
    policy.validate()?;
    if policy.policy_id != summary.policy_id
        || policy.account_id != summary.account_id
        || policy.version != summary.version
    {
        anyhow::bail!("active recovery policy summary does not match its signed policy body");
    }

    let agreement_ref = policy
        .active_hpke_recipients(chrono::Utc::now())
        .into_iter()
        .find(|entry| {
            entry.public_key_multibase.as_str() == key_material.backup_hpke_public_key_multikey
        })
        .map(|entry| &entry.key_agreement_ref);
    let Some(agreement_ref) = agreement_ref else {
        anyhow::bail!(
            "supplied Recovery Key does not match the active policy backup recipient; use the staged recovery-key handoff workflow"
        );
    };
    let proof_key = policy.signing_keys().into_iter().find(|entry| {
        &entry.backup_hpke.key_agreement_ref == agreement_ref
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
    let recovery_secret_ref =
        validate_active_policy_key_material(policy, &session.account_id, &key_material)?;
    arkret_sdk::identity_root::build_recovery_unlock_proof(
        session,
        recovery_secret_ref.as_str(),
        &key_material,
    )
    .map_err(anyhow::Error::from)
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
    use super::*;

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
