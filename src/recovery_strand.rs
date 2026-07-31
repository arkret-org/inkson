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
    RecoveryKeySignatureAlgorithm, RecoveryPolicy, RecoveryPolicyActiveOutcome,
    RecoveryPolicyAuthData, RecoveryPolicyRef, RecoveryPolicySummary, RecoveryProofKind,
    RecoveryPublicationAuthorizationRule, RecoverySessionCreateRequestBody,
    RecoverySessionProofSubmitRequestBody,
};
use arkret_sdk::{DeviceId, Did, DidUrl, NonEmptyString, PolicyId, TypedTrustDomainId};
use arkret_wire::{AuthoritySetIssuer, AuthoritySetIssuerRole};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::transport::TransportClient;

pub const RECOVERY_POLICY_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "publication_authorization_rules",
    "recovery_keys",
    "recovery_key_agreements",
    "supersedes",
    "issued_at",
    "expires_at",
];

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
    let mut typed_policy = RecoveryPolicy {
        schema: "ak.schema.recovery_policy.v1".to_owned(),
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
            alg: RecoveryKeySignatureAlgorithm::Ed25519,
            not_before: issued_at,
            expires_at: key_expires_at,
            revoked_at: None,
        }]),
        recovery_key_agreements: Some(vec![RecoveryKeyAgreementEntry {
            key_agreement_ref: backup_hpke_ref,
            alg: RecoveryKeyAgreementAlgorithm::X25519,
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
        auth_data: RecoveryPolicyAuthData {
            // §2.2: the policy auth_data verification method is a DID URL.
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned()).map_err(
                |error| anyhow::anyhow!("recovery policy verification method is invalid: {error}"),
            )?,
            signature_algorithm: "Ed25519".to_owned(),
            signature: String::new(),
            signed_fields: RECOVERY_POLICY_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        },
        extra: Default::default(),
    };
    typed_policy.validate()?;
    let mut policy = serde_json::to_value(&typed_policy)?;
    let transcript = recovery_policy_signature_transcript(&policy, RECOVERY_POLICY_SIGNED_FIELDS);
    let bytes = crate::canonical::canonical_json_bytes(&transcript)?;
    let signature =
        sign_raw(&bytes).map_err(|err| anyhow::anyhow!("recovery policy sign: {err:?}"))?;
    policy["auth_data"]["signature"] = Value::String(B64.encode(signature));
    typed_policy = serde_json::from_value(policy.clone())?;
    typed_policy.validate()?;
    Ok(policy)
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

fn recovery_policy_signature_transcript(payload: &Value, signed_fields: &[&str]) -> Value {
    let mut signed_payload = Map::new();
    for field in signed_fields {
        signed_payload.insert(
            (*field).to_owned(),
            payload.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    json!({
        "type": "ak.identity.recovery_policy.signature.v1",
        "signed_fields": signed_fields,
        "payload": Value::Object(signed_payload),
    })
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
    let payload = arkret_sdk::RecoveryPolicySetPayload {
        policy_id: policy.policy_id.clone(),
        value: policy,
    };
    payload.validate()?;
    let event = crate::operation::OperationBuilder::new(
        realm_id,
        principal_id,
        arkret_sdk::events::kinds::EventKind::PolicySet,
    )
    .body(serde_json::to_value(payload)?)
    .build_sdk_event("inkson-recovery-policy")?;
    let submitter = api.event_submitter()?;
    let (event, _) = submitter.prepare_sdk_event_for_submit(&event).await?;
    let http = api.sdk_http_client()?;
    crate::authorization_lease::ensure_for_events(&http, std::slice::from_ref(&event)).await?;
    let submission = crate::authorization_lease::standard_initial_submission(&http, &event).await?;
    let request = arkret_sdk::RecoveryPolicyPublishRequest {
        event: submission.event,
        authorization_lease: submission.authorization_lease,
        cba_proof_bundles: submission.cba_proof_bundles,
        control_proposal_receipt: submission.control_proposal_receipt,
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
        .events_query_all_pages(policy_event.realm_id.as_str())
        .await?;
    let create = events
        .events
        .iter()
        .find(|event| {
            event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE
                && event.actor_id.as_str() == principal_id
        })
        .ok_or_else(|| anyhow::anyhow!("self-PCR history omitted its bootstrap create Event"))?;
    let authorize = events
        .events
        .iter()
        .find(|event| {
            event.kind.as_str() == arkret_sdk::events::EventKind::DEVICE_AUTHORIZE
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
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<arkret_sdk::http_client::Error>(),
            Some(arkret_sdk::http_client::Error::Api { error, .. })
                if error.code() == "frontier_unavailable"
        ) || matches!(
            cause.downcast_ref::<arkret_sdk::Error>(),
            Some(arkret_sdk::Error::Api { error, .. })
                if error.code() == "frontier_unavailable"
        )
    })
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
    let plaintext = crate::canonical::canonical_json_bytes(&json!({
        "schema": "ak.local.did_recovery_metadata.v1",
        "principal_id": principal_id,
        "root_generation": key_material.root_generation,
        "root_public_key_multibase": key_material.root_public_key_multikey,
        "next_root_public_key_multibase": key_material.next_root_public_key_multikey,
        "next_root_key_hash": key_material.next_root_key_hash,
        "recovery_policy_ref": {
            "policy_id": policy.policy_id.as_str(),
            "policy_version": policy.version,
        },
        "created_at": created_at,
    }))?;
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
    api.put_key_backup(&backup_id, body).await?;
    Ok(backup_id)
}

pub fn build_recovery_directed_ssk_backup_body(
    principal_id: &str,
    device_id: &str,
    policy: &ActiveRecoveryPolicy,
    publish: &arkret_sdk::CrossSigningPublish,
    self_signing_key: &SigningKey,
) -> anyhow::Result<Value> {
    if publish.principal_id.as_str() != principal_id || policy.principal_id.as_str() != principal_id
    {
        anyhow::bail!("cross-signing recovery backup principal mismatch");
    }
    let generation = publish.generation.get();
    if self_signing_key.verifying_key().to_bytes()
        != decode_ed25519_public_multikey(publish.self_signing_key.public_key.as_str())?
    {
        anyhow::bail!("self-signing private key does not match accepted publish");
    }
    let policy_body = policy
        .policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("active recovery policy omits closed policy body"))?;
    let agreement = policy_body
        .recovery_key_agreements
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|entry| {
            entry.usage == RecoveryKeyAgreementUse::BackupHpke
                && entry.alg == RecoveryKeyAgreementAlgorithm::X25519
                && entry
                    .hpke_suites
                    .contains(&RecoveryHpkeSuite::X25519ChaCha20Poly1305)
                && entry.revoked_at.is_none()
        })
        .ok_or_else(|| anyhow::anyhow!("active recovery policy has no usable backup HPKE key"))?;
    let recovery_public_key =
        decode_x25519_public_multikey(agreement.public_key_multibase.as_str())?;
    let backup_id = format!("ak:backup:{}", crate::operation::uuid_v7());
    let seed = Zeroizing::new(B64.encode(self_signing_key.to_bytes()));
    let plaintext = Zeroizing::new(crate::canonical::canonical_json_bytes(&json!({
        "schema": "ak.local.cross_signing_recovery.v1",
        "principal_id": principal_id,
        "ssk_generation": generation,
        "self_signing_key_kid": publish.self_signing_key.kid.as_str(),
        "self_signing_key_seed_b64url": seed.as_str(),
        "recovery_policy_ref": {
            "policy_id": policy.policy_id.as_str(),
            "policy_version": policy.version,
        },
    }))?);
    crate::key_backup::build_recovery_public_key_backup_body(
        &backup_id,
        principal_id,
        device_id,
        &recovery_public_key,
        agreement.key_agreement_ref.as_str(),
        crate::key_backup::BackupKind::SecretStorage,
        "cross_signing_recovery",
        &KeyBackupContentItem {
            item_kind: "self_signing_key".to_owned(),
            secret_id: Some(publish.self_signing_key.kid.as_str().to_owned()),
            secret_version: Some(u32::try_from(generation).map_err(|_| {
                anyhow::anyhow!("cross-signing generation exceeds backup secret version range")
            })?),
            ..Default::default()
        },
        &plaintext,
        Some((policy.policy_id.as_str(), policy.version)),
    )
}

pub async fn ensure_recovery_directed_ssk_backup(
    api: &TransportClient,
    principal_id: &str,
    device_id: &str,
    publish: &arkret_sdk::CrossSigningPublish,
    self_signing_key: &SigningKey,
) -> anyhow::Result<String> {
    let policy = fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("active recovery policy is unavailable"))?;
    let generation = publish.generation.get();
    let list = crate::mls::account_recovery::fetch_mls_restore_payload(api, principal_id).await?;
    let active_series_id = list
        .get("active_series")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|record| {
            record.get("schema").and_then(Value::as_str)
                == Some(crate::key_backup::KEY_BACKUP_ACTIVE_SERIES_SCHEMA)
                && record.get("backup_kind").and_then(Value::as_str)
                    == Some(crate::key_backup::BackupKind::SecretStorage.as_str())
        })
        .and_then(|record| record.get("active_series_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("secret_storage active-series pointer is unavailable"))?;
    let active_backups = list
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| {
            backup.get("series_id").and_then(Value::as_str) == Some(active_series_id)
                && backup.get("backup_kind").and_then(Value::as_str)
                    == Some(crate::key_backup::BackupKind::SecretStorage.as_str())
        })
        .collect::<Vec<_>>();
    if let Some(existing) = list
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|backup| {
            backup.get("series_id").and_then(Value::as_str) == Some(active_series_id)
                && backup.get("backup_kind").and_then(Value::as_str) == Some("secret_storage")
                && backup
                    .get("recovery_policy_ref")
                    .and_then(|value| value.get("policy_id"))
                    .and_then(Value::as_str)
                    == Some(policy.policy_id.as_str())
                && backup
                    .get("recovery_policy_ref")
                    .and_then(|value| value.get("policy_version"))
                    .and_then(Value::as_u64)
                    == Some(policy.version)
                && backup
                    .get("contents")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|item| {
                        item.get("item_kind").and_then(Value::as_str) == Some("self_signing_key")
                            && item.get("secret_id").and_then(Value::as_str)
                                == Some(publish.self_signing_key.kid.as_str())
                            && item.get("secret_version").and_then(Value::as_u64)
                                == Some(generation)
                    })
        })
        .and_then(|backup| backup.get("backup_id"))
        .and_then(Value::as_str)
    {
        return Ok(existing.to_owned());
    }
    let mut body = build_recovery_directed_ssk_backup_body(
        principal_id,
        device_id,
        &policy,
        publish,
        self_signing_key,
    )?;
    let previous = active_backups
        .into_iter()
        .max_by_key(|backup| {
            backup
                .get("series_seq")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .ok_or_else(|| anyhow::anyhow!("active secret_storage series has no tail"))?;
    crate::mls::account_recovery::apply_next_series(Some(previous), &mut body)?;
    let backup_id = body
        .get("backup_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("recovery-directed SSK backup omits backup_id"))?
        .to_owned();
    api.put_key_backup(&backup_id, body).await?;
    Ok(backup_id)
}

pub struct RecoveredSelfSigningKey {
    pub generation: u64,
    pub kid: String,
    pub signing_key: SigningKey,
}

pub fn open_recovery_directed_ssk_backup(
    body: &Value,
    recovery_private_key: &[u8],
    principal_id: &str,
    snapshot_generation: u64,
) -> anyhow::Result<RecoveredSelfSigningKey> {
    if body.get("backup_kind").and_then(Value::as_str) != Some("secret_storage") {
        anyhow::bail!("recovery-directed SSK envelope is not secret_storage");
    }
    let content = body
        .get("contents")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("item_kind").and_then(Value::as_str) == Some("self_signing_key")
            })
        })
        .ok_or_else(|| anyhow::anyhow!("recovery-directed envelope omits self_signing_key"))?;
    if content.get("secret_version").and_then(Value::as_u64) != Some(snapshot_generation) {
        anyhow::bail!("recovery-directed SSK envelope generation does not match session snapshot");
    }
    let content_kid = content
        .get("secret_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("recovery-directed SSK envelope omits key id"))?;
    let opened = Zeroizing::new(crate::key_backup::open_recovery_public_key_backup_body(
        recovery_private_key,
        body,
    )?);
    let mut plaintext: Value = serde_json::from_slice(&opened)
        .map_err(|error| anyhow::anyhow!("parse recovery-directed SSK plaintext: {error}"))?;
    if plaintext.get("schema").and_then(Value::as_str) != Some("ak.local.cross_signing_recovery.v1")
        || plaintext.get("principal_id").and_then(Value::as_str) != Some(principal_id)
        || plaintext.get("ssk_generation").and_then(Value::as_u64) != Some(snapshot_generation)
        || plaintext
            .get("self_signing_key_kid")
            .and_then(Value::as_str)
            != Some(content_kid)
    {
        anyhow::bail!("recovery-directed SSK plaintext binding mismatch");
    }
    let seed_value = plaintext
        .get_mut("self_signing_key_seed_b64url")
        .ok_or_else(|| anyhow::anyhow!("recovery-directed SSK plaintext omits private seed"))?
        .take();
    let seed_b64 = match seed_value {
        Value::String(value) => Zeroizing::new(value),
        _ => anyhow::bail!("recovery-directed SSK private seed has invalid shape"),
    };
    let seed_bytes = Zeroizing::new(
        B64.decode(seed_b64.as_bytes())
            .map_err(|error| anyhow::anyhow!("decode recovery-directed SSK seed: {error}"))?,
    );
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(seed_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("recovery-directed SSK seed must be 32 bytes"))?,
    );
    Ok(RecoveredSelfSigningKey {
        generation: snapshot_generation,
        kid: content_kid.to_owned(),
        signing_key: SigningKey::from_bytes(&seed),
    })
}

fn decode_x25519_public_multikey(value: &str) -> anyhow::Result<Vec<u8>> {
    let decoded = arkret_sdk::decode_multibase_base58btc(value)
        .map_err(|error| anyhow::anyhow!("backup HPKE public key is invalid: {error}"))?;
    let (codec, header_len) = arkret_sdk::decode_multicodec_varint(&decoded)
        .ok_or_else(|| anyhow::anyhow!("backup HPKE public key has no multicodec"))?;
    if codec != 0xec || decoded.len().saturating_sub(header_len) != 32 {
        anyhow::bail!("backup HPKE public key is not a 32-byte X25519 multikey");
    }
    Ok(decoded[header_len..].to_vec())
}

fn decode_ed25519_public_multikey(value: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = arkret_sdk::decode_multibase_base58btc(value)
        .map_err(|error| anyhow::anyhow!("self-signing public key is invalid: {error}"))?;
    let (codec, header_len) = arkret_sdk::decode_multicodec_varint(&decoded)
        .ok_or_else(|| anyhow::anyhow!("self-signing public key has no multicodec"))?;
    if codec != 0xed || decoded.len().saturating_sub(header_len) != 32 {
        anyhow::bail!("self-signing public key is not a 32-byte Ed25519 multikey");
    }
    decoded[header_len..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("self-signing public key length changed during decode"))
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
    principal_signing_key: &SigningKey,
) -> anyhow::Result<Value> {
    let proof = crate::recovery_proof::build_principal_signing_proof(
        session,
        verification_method,
        principal_signing_key,
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

#[cfg(test)]
mod tests {
    use arkret_models_crypto::RecoveryProofKind;
    use serde_json::json;

    use super::*;

    fn identity_recovery_key_material() -> arkret_sdk::identity_root::IdentityRecoveryKeyMaterial {
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "",
            0,
        )
        .expect("identity recovery KDF")
    }

    fn test_active_policy(policy_id: &str, version: u64) -> ActiveRecoveryPolicy {
        let issued_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:01.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        ActiveRecoveryPolicy {
            policy_id: PolicyId::new(policy_id.to_owned()).unwrap(),
            principal_id: Did::new("did:web:alice.example".to_owned()).unwrap(),
            version,
            acceptance_basis: arkret_wire::LeaseBasisRef::Seal(
                arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            recovery_policy_ref: None,
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland.local".to_owned())
                .unwrap(),
            allowed_proof_kinds: vec![RecoveryProofKind::RecoveryUnlock],
            supersedes: None,
            expires_at: None,
            issued_at,
            accepted_at,
            policy: None,
        }
    }

    fn active_policy_with_material(
        material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    ) -> ActiveRecoveryPolicy {
        let principal_id = "did:web:alice.example";
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [7u8; 32],
            principal_id,
            format!("{principal_id}#device-1"),
        );
        let value = build_signed_genesis_recovery_policy_with_signer(
            principal_id,
            "ak:trust_domain:soland.local",
            material,
            &signer,
        )
        .expect("signed policy");
        let policy: RecoveryPolicy = serde_json::from_value(value).expect("typed policy");
        ActiveRecoveryPolicy {
            policy_id: policy.policy_id.clone(),
            principal_id: policy.principal_id.clone(),
            version: policy.version,
            acceptance_basis: arkret_wire::LeaseBasisRef::Seal(
                arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap(),
            ),
            recovery_policy_ref: None,
            trust_domain: policy.trust_domain.clone(),
            allowed_proof_kinds: policy.allowed_proof_kinds.clone(),
            supersedes: policy.supersedes.clone(),
            expires_at: policy.expires_at,
            issued_at: policy.issued_at,
            accepted_at: policy.issued_at + chrono::Duration::seconds(1),
            policy: Some(policy),
        }
    }

    #[test]
    fn active_policy_must_match_both_recovery_key_roles() {
        let material = identity_recovery_key_material();
        let policy = active_policy_with_material(&material);
        validate_active_policy_key_material(&policy, "did:web:alice.example", &material)
            .expect("matching signing and HPKE keys");

        let replacement =
            arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "replacement",
                0,
            )
            .expect("replacement generation");
        let error =
            validate_active_policy_key_material(&policy, "did:web:alice.example", &replacement)
                .expect_err("unaccepted replacement must fail closed");
        assert!(error.to_string().contains("staged recovery-key handoff"));
    }

    #[test]
    fn recovery_directed_ssk_backup_round_trips_only_with_recovery_hpke_key() {
        let material = identity_recovery_key_material();
        let policy = active_policy_with_material(&material);
        let principal = Did::new("did:web:alice.example".to_owned()).unwrap();
        let output = crate::cross_signing::CrossSigningExecutor::new(
            crate::cross_signing::CrossSigningSetupPlan::build_initial(
                principal.as_str(),
                "ak:device:019a6aa0-0000-7000-8000-000000000099",
            ),
            principal,
            TypedTrustDomainId::new("ak:trust_domain:soland.local".to_owned()).unwrap(),
        )
        .run()
        .unwrap();
        let body = build_recovery_directed_ssk_backup_body(
            "did:web:alice.example",
            "ak:device:019a6aa0-0000-7000-8000-000000000099",
            &policy,
            &output.publish_content,
            &output.self_signing_key,
        )
        .unwrap();

        assert_eq!(body["backup_kind"], "secret_storage");
        assert_eq!(body["contents"][0]["item_kind"], "self_signing_key");
        assert!(
            body.to_string()
                .find(&B64.encode(output.self_signing_key.to_bytes()))
                .is_none()
        );
        let recovered = open_recovery_directed_ssk_backup(
            &body,
            &material.backup_hpke_derived_private_key,
            "did:web:alice.example",
            1,
        )
        .unwrap();
        assert_eq!(
            recovered.signing_key.to_bytes(),
            output.self_signing_key.to_bytes()
        );
        assert_eq!(recovered.generation, 1);
        assert_eq!(
            recovered.kid,
            output.publish_content.self_signing_key.kid.as_str()
        );
        assert!(
            open_recovery_directed_ssk_backup(
                &body,
                &material.backup_hpke_derived_private_key,
                "did:web:alice.example",
                2,
            )
            .is_err()
        );
    }

    #[test]
    fn create_session_body_matches_schema_shape() {
        let body = create_session_body(
            "did:web:alice.example",
            "ak:device:019a6aa0-0000-7000-8000-000000000099",
            "ak:trust_domain:soland.local",
            None,
        )
        .unwrap();
        let body = serde_json::to_value(body).unwrap();
        assert_eq!(body["principal_id"], "did:web:alice.example");
        assert!(body.get("ssk_generation").is_none());
        assert!(body.get("expected_recovery_policy_ref").is_none());
    }

    #[test]
    fn create_session_body_includes_cas_hint() {
        let body = create_session_body(
            "did:web:alice.example",
            "ak:device:019a6aa0-0000-7000-8000-000000000099",
            "ak:trust_domain:soland.local",
            Some(("ak:policy:019a6aa0-0000-7000-8000-0000000000bb", 1)),
        )
        .unwrap();
        let body = serde_json::to_value(body).unwrap();
        assert_eq!(
            body["expected_recovery_policy_ref"]["policy_id"],
            "ak:policy:019a6aa0-0000-7000-8000-0000000000bb"
        );
        assert_eq!(body["expected_recovery_policy_ref"]["policy_version"], 1);
    }

    #[test]
    fn parse_active_policy_handles_null_and_value() {
        assert!(parse_active_recovery_policy(&json!({ "active_policy": null })).is_none());
        assert!(
            parse_active_recovery_policy(&json!({
                "active_policy": {
                    "policy_id": "",
                    "principal_id": "did:web:alice.example",
                    "version": 1,
                    "trust_domain": "ak:trust_domain:soland.local",
                    "allowed_proof_kinds": [],
                    "issued_at": "2026-01-01T00:00:00.000Z",
                    "accepted_at": "2026-01-01T00:00:01.000Z"
                }
            }))
            .is_none()
        );
        let parsed = parse_active_recovery_policy(&json!({
            "active_policy": {
                "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "principal_id": "did:web:alice.example",
                "version": 3,
                "acceptance_basis": format!("ak:seal:sha256:{}", "a".repeat(64)),
                "trust_domain": "ak:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing", "recovery_unlock"],
                "issued_at": "2026-01-01T00:00:00.000Z",
                "accepted_at": "2026-01-01T00:00:01.000Z"
            }
        }))
        .expect("active policy");
        assert_eq!(parsed.version, 3);
        assert_eq!(
            parsed.allowed_proof_kinds,
            vec![
                RecoveryProofKind::PrincipalSigning,
                RecoveryProofKind::RecoveryUnlock
            ]
        );
    }

    #[test]
    fn genesis_recovery_policy_requires_principal_scoped_signer() {
        let signer = crate::event_signer::build_ed25519_signer([7u8; 32], "did:key:zlocal");
        let err = build_signed_genesis_recovery_policy_with_signer(
            "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f",
            "ak:trust_domain:local.host",
            &identity_recovery_key_material(),
            &signer,
        )
        .expect_err("did:key device signer must not publish a did:webvh policy");

        assert!(
            err.to_string().contains("is not scoped to principal_id"),
            "{err}"
        );
    }

    #[test]
    fn genesis_recovery_policy_uses_principal_scoped_verification_method() {
        let signer = crate::event_signer::build_ed25519_signer(
            [8u8; 32],
            "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f",
        );
        let policy = build_signed_genesis_recovery_policy_with_signer(
            "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f",
            "ak:trust_domain:local.host",
            &identity_recovery_key_material(),
            &signer,
        )
        .expect("principal-scoped signer should build policy");

        assert_eq!(
            policy["auth_data"]["verification_method"],
            "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f#device"
        );
        assert!(
            policy["auth_data"]["signature"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }

    #[test]
    fn genesis_recovery_policy_accepts_explicit_principal_signing_method() {
        let principal_id = "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f";
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [8u8; 32],
            principal_id,
            format!("{principal_id}#did-key-1"),
        );
        let policy = build_signed_genesis_recovery_policy_with_signer(
            principal_id,
            "ak:trust_domain:local.host",
            &identity_recovery_key_material(),
            &signer,
        )
        .expect("principal signing key should build policy");

        assert_eq!(
            policy["auth_data"]["verification_method"],
            format!("{principal_id}#did-key-1")
        );
        assert!(
            policy["auth_data"]["signature"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }

    #[test]
    fn genesis_recovery_policy_for_session_device_reuses_active_device_key() {
        let principal_id = "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f";
        let device_id = "ak:device:01964137-0000-7000-8000-000000000001";
        let seed = [42u8; 32];
        let device_signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            seed,
            "did:key:zlocal-device",
            device_id,
        ));
        let _signer_guard =
            crate::event_signer::ActiveSignerTestGuard::replace(Some(device_signer));

        let policy = build_signed_genesis_recovery_policy_for_session_device(
            principal_id,
            "ak:trust_domain:local.host",
            device_id,
            &identity_recovery_key_material(),
        )
        .expect("active device signer should sign principal-scoped recovery policy");

        assert_eq!(
            policy["auth_data"]["verification_method"],
            format!("{principal_id}#{device_id}")
        );
        assert_ne!(
            policy["recovery_keys"][0]["public_key_multibase"],
            policy["recovery_key_agreements"][0]["public_key_multibase"]
        );
        assert_eq!(
            policy["recovery_keys"][0]["key_agreement_ref"],
            policy["recovery_key_agreements"][0]["key_agreement_ref"]
        );

        let transcript =
            recovery_policy_signature_transcript(&policy, RECOVERY_POLICY_SIGNED_FIELDS);
        let bytes = crate::canonical::canonical_json_bytes(&transcript).expect("canonical bytes");
        let raw_signature = B64
            .decode(
                policy["auth_data"]["signature"]
                    .as_str()
                    .expect("signature")
                    .as_bytes(),
            )
            .expect("signature base64url");
        let signature =
            ed25519_dalek::Signature::from_slice(&raw_signature).expect("ed25519 signature");
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        ed25519_dalek::Verifier::verify(&verifying_key, &bytes, &signature)
            .expect("policy must be signed by the active device key");
    }

    #[test]
    fn account_recovery_state_requires_policy_and_did_recovery_backup() {
        let policy = json!({
            "active_policy": {
                "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "principal_id": "did:web:alice.example",
                "version": 1,
                "acceptance_basis": format!("ak:seal:sha256:{}", "a".repeat(64)),
                "trust_domain": "ak:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing"],
                "issued_at": "2026-01-01T00:00:00.000Z",
                "accepted_at": "2026-01-01T00:00:01.000Z"
            }
        });
        let no_backup =
            account_recovery_state_from_payloads(&policy, &json!({"backups": []}), None);
        assert!(!no_backup.server_recovery_configured());

        let missing_policy_ref = account_recovery_state_from_payloads(
            &policy,
            &json!({
                "backups": [{
                    "backup_kind": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" }
                }]
            }),
            None,
        );
        assert!(!missing_policy_ref.server_recovery_configured());

        let configured = account_recovery_state_from_payloads(
            &policy,
            &json!({
                "backups": [{
                    "backup_kind": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                        "policy_version": 1
                    },
                    "series_seq": 0
                }]
            }),
            None,
        );
        assert!(configured.server_recovery_configured());

        let wrong_policy = account_recovery_state_from_payloads(
            &policy,
            &json!({
                "backups": [{
                    "backup_kind": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ak:policy:019a6aa0-0000-7000-8000-000000000000",
                        "policy_version": 1
                    },
                    "series_seq": 0
                }]
            }),
            None,
        );
        assert!(!wrong_policy.server_recovery_configured());
    }

    #[test]
    fn matching_did_recovery_backup_requires_active_policy_ref() {
        let policy = test_active_policy("ak:policy:019a6aa0-0000-7000-8000-0000000000bb", 2);
        let payload = json!({
            "backups": [
                {
                    "backup_id": "ak:backup:019a6aa0-0000-7000-8000-000000000001",
                    "backup_kind": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ak:policy:019a6aa0-0000-7000-8000-000000000000",
                        "policy_version": 2
                    }
                },
                {
                    "backup_id": "ak:backup:019a6aa0-0000-7000-8000-000000000002",
                    "backup_kind": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                        "policy_version": 2
                    },
                    "series_seq": 0
                }
            ]
        });
        assert_eq!(
            matching_did_recovery_first_backup_id(&payload, &policy).as_deref(),
            Some("ak:backup:019a6aa0-0000-7000-8000-000000000002")
        );
    }

    #[test]
    fn matching_did_recovery_backup_rejects_non_first_series_seq_when_present() {
        let policy = test_active_policy("ak:policy:019a6aa0-0000-7000-8000-0000000000bb", 2);
        let payload = json!({
            "backups": [{
                "backup_id": "ak:backup:019a6aa0-0000-7000-8000-000000000002",
                "backup_kind": "did_recovery",
                "encryption": { "recipient_method": "recovery_public_key" },
                "recovery_policy_ref": {
                    "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                    "policy_version": 2
                },
                "series_seq": 1
            }]
        });
        assert_eq!(
            matching_did_recovery_first_backup_id(&payload, &policy),
            None
        );
    }

    #[test]
    fn first_backup_gate_status_requires_active_policy_and_matching_backup() {
        let policy = json!({
            "active_policy": {
                "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "principal_id": "did:web:alice.example",
                "version": 1,
                "acceptance_basis": format!("ak:seal:sha256:{}", "a".repeat(64)),
                "trust_domain": "ak:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing"],
                "issued_at": "2026-01-01T00:00:00.000Z",
                "accepted_at": "2026-01-01T00:00:01.000Z"
            }
        });
        assert_eq!(
            first_backup_gate_status_from_payloads(
                &json!({ "active_policy": null }),
                &json!({ "backups": [] })
            ),
            FirstBackupGateStatus::Blocked(FirstBackupGateBlockReason::NoActiveRecoveryPolicy)
        );
        assert_eq!(
            first_backup_gate_status_from_payloads(&policy, &json!({ "backups": [] })),
            FirstBackupGateStatus::Blocked(
                FirstBackupGateBlockReason::NoMatchingDidRecoveryBackup {
                    policy_id: "ak:policy:019a6aa0-0000-7000-8000-0000000000bb".to_owned(),
                    policy_version: 1,
                },
            )
        );
        assert_eq!(
            first_backup_gate_status_from_payloads(
                &policy,
                &json!({
                    "backups": [{
                        "backup_id": "ak:backup:019a6aa0-0000-7000-8000-000000000002",
                        "backup_kind": "did_recovery",
                        "encryption": { "recipient_method": "recovery_public_key" },
                        "recovery_policy_ref": {
                            "policy_id": "ak:policy:019a6aa0-0000-7000-8000-0000000000bb",
                            "policy_version": 1
                        },
                        "series_seq": 0
                    }]
                })
            ),
            FirstBackupGateStatus::Satisfied {
                backup_id: "ak:backup:019a6aa0-0000-7000-8000-000000000002".to_owned(),
            }
        );
    }

    #[test]
    fn local_fingerprint_without_server_backup_is_incomplete() {
        let state = account_recovery_state_from_payloads(
            &json!({ "active_policy": null }),
            &json!({"backups": []}),
            Some(" sha256:abc ".to_owned()),
        );
        assert!(state.local_only_recovery_key());
        assert!(!state.server_recovery_configured());
    }
}
