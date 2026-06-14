//! 6.1 / 6.3 — recovery client orchestration.
//!
//! Pure request builders (unit-tested) + thin async wrappers over
//! [`crate::api::CokretApi`] that drive the REC-1 recovery strand:
//!
//! - 6.1: fetch + parse the active recovery policy.
//! - 6.3: open a recovery session, sign + submit a `principal_signing` proof, then complete with
//!   client-supplied `ck.device.authorize` material.
//!
//! The wire shapes match `cokret-spec` `recovery-session.schema.json`
//! (`create_request` / `proof_submit_request` / `complete_request`).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use cokret_sdk::models::{
    RecoveryPolicyRef, RecoverySessionCompleteRequestBody, RecoverySessionCreateRequestBody,
    RecoverySessionProofSubmitRequestBody,
};
use cokret_sdk::{DeviceId, Did, EventId, PolicyId, TypedTrustDomainId};
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};

use crate::api::CokretApi;

pub const RECOVERY_POLICY_SIGNED_FIELDS: &[&str] = &[
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "supersedes",
    "issued_at",
    "expires_at",
];

/// 6.1 — parsed active recovery policy summary (the fields a client surfaces).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveRecoveryPolicy {
    pub policy_id: String,
    pub policy_version: u64,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
}

/// Account-level recovery state derived from server facts plus optional local
/// display metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountRecoveryState {
    pub active_policy: Option<ActiveRecoveryPolicy>,
    pub did_recovery_backup_count: usize,
    pub recovery_public_key_secret_storage_backup_count: usize,
    pub local_recovery_key_fingerprint: Option<String>,
}

impl AccountRecoveryState {
    /// The account is recoverable only when the server has both the accepted
    /// policy and the DID recovery backup required by the first-backup gate.
    pub fn server_recovery_configured(&self) -> bool {
        self.active_policy.is_some() && self.did_recovery_backup_count > 0
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
    let p = response.get("active_policy").filter(|v| !v.is_null())?;
    Some(ActiveRecoveryPolicy {
        policy_id: p
            .get("policy_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        policy_version: p.get("version").and_then(Value::as_u64).unwrap_or_default(),
        trust_domain: p
            .get("trust_domain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        allowed_proof_kinds: p
            .get("allowed_proof_kinds")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn account_recovery_state_from_payloads(
    recovery_policy_response: &Value,
    backup_list_payload: &Value,
    local_recovery_key_fingerprint: Option<String>,
) -> AccountRecoveryState {
    AccountRecoveryState {
        active_policy: parse_active_recovery_policy(recovery_policy_response),
        did_recovery_backup_count: count_backups_by_class_and_method(
            backup_list_payload,
            "did_recovery",
            "recovery_public_key",
        ),
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
    backup_class: &str,
    recipient_method: &str,
) -> usize {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| {
            backup.get("backup_class").and_then(Value::as_str) == Some(backup_class)
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
    api: &CokretApi,
) -> anyhow::Result<Option<ActiveRecoveryPolicy>> {
    let response = api.get_recovery_policy().await?;
    Ok(parse_active_recovery_policy(&response))
}

pub fn build_signed_genesis_recovery_policy(
    principal_id: &str,
    trust_domain: &str,
) -> anyhow::Result<Value> {
    if let Some(signer) = crate::event_signer::active_signer() {
        if principal_scoped_recovery_policy_verification_method(principal_id, &signer).is_ok() {
            return build_signed_genesis_recovery_policy_with_signer(
                principal_id,
                trust_domain,
                &signer,
            );
        }
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
) -> anyhow::Result<Value> {
    if let Some(signer) = crate::event_signer::active_signer() {
        if principal_scoped_recovery_policy_verification_method(principal_id, &signer).is_ok() {
            return build_signed_genesis_recovery_policy_with_signer(
                principal_id,
                trust_domain,
                &signer,
            );
        }
    }

    let signer = default_principal_scoped_recovery_policy_signer(principal_id, device_id)?;
    build_signed_genesis_recovery_policy_with_signer(principal_id, trust_domain, &signer)
}

fn default_principal_scoped_recovery_policy_signer(
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<crate::event_signer::YougenEventSigner> {
    let principal_id = principal_id.trim();
    if principal_id.is_empty() {
        anyhow::bail!("principal_id is required");
    }
    let device_id = device_id.trim();
    if device_id.is_empty() {
        anyhow::bail!("device_id is required");
    }
    let store = crate::secure_key_store::default_secure_key_store("yougen");
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
    signer: &crate::event_signer::YougenEventSigner,
) -> anyhow::Result<Value> {
    let principal_id = principal_id.trim();
    let trust_domain = trust_domain.trim();
    if principal_id.is_empty() {
        anyhow::bail!("principal_id is required");
    }
    if trust_domain.is_empty() {
        anyhow::bail!("trust_domain is required");
    }
    let verification_method =
        principal_scoped_recovery_policy_verification_method(principal_id, signer)?;
    let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut policy = json!({
        "schema": "ck.schema.recovery_policy.v1",
        "policy_id": format!("ck:policy:{}", crate::operation::uuid_v7()),
        "principal_id": principal_id,
        "version": 1,
        "supersedes": null,
        "trust_domain": trust_domain,
        "allowed_proof_kinds": ["principal_signing", "recovery_unlock"],
        "issued_at": issued_at,
        "expires_at": null,
        "auth_data": {
            "verification_method": verification_method,
            "signature_algorithm": "Ed25519",
            "signed_fields": RECOVERY_POLICY_SIGNED_FIELDS,
            "signature": ""
        }
    });
    let transcript = recovery_policy_signature_transcript(&policy, RECOVERY_POLICY_SIGNED_FIELDS);
    let bytes = crate::canonical::canonical_json_bytes(&transcript)?;
    let signature = signer
        .sign_raw(&bytes)
        .map_err(|err| anyhow::anyhow!("recovery policy sign: {err:?}"))?;
    policy["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(policy)
}

fn principal_scoped_recovery_policy_verification_method<'a>(
    principal_id: &str,
    signer: &'a crate::event_signer::YougenEventSigner,
) -> anyhow::Result<&'a str> {
    let verification_method = signer.verification_method().trim();
    if verification_method
        .strip_prefix(principal_id)
        .and_then(|rest| rest.strip_prefix('#'))
        .is_some_and(|fragment| !fragment.trim().is_empty())
    {
        return Ok(verification_method);
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
        "type": "ck.identity.recovery_policy.signature.v1",
        "signed_fields": signed_fields,
        "payload": Value::Object(signed_payload),
    })
}

pub async fn ensure_active_recovery_policy(
    api: &CokretApi,
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<ActiveRecoveryPolicy> {
    if let Some(policy) = fetch_active_recovery_policy(api).await? {
        return Ok(policy);
    }

    let description = api.describe().await?;
    let body = build_signed_genesis_recovery_policy_for_session_device(
        principal_id,
        description.trust_domain.as_str(),
        device_id,
    )?;
    api.put_recovery_policy(body).await?;

    fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server accepted recovery policy but did not expose it"))
}

pub async fn ensure_recovery_policy_and_did_recovery_backup(
    api: &CokretApi,
    principal_id: &str,
    device_id: &str,
    recovery_key: &str,
) -> anyhow::Result<String> {
    let policy = ensure_active_recovery_policy(api, principal_id, device_id).await?;
    let list = api
        .list_key_backups_by_series(None, Some("did_recovery"))
        .await?;
    if let Some(backup_id) = matching_did_recovery_backup_id(&list, &policy) {
        return Ok(backup_id);
    }

    let (recovery_private_key, recovery_public_key) =
        crate::hpke_backup::derive_recovery_keypair_from_recovery_key(recovery_key)?;
    let backup_id = format!("ck:backup:{}", crate::operation::uuid_v7());
    let recovery_key_ref = format!("{}#recovery", principal_id.trim());
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let plaintext = crate::canonical::canonical_json_bytes(&json!({
        "schema": "ck.local.did_recovery_share.v1",
        "principal_id": principal_id,
        "recovery_key_ref": recovery_key_ref,
        "recovery_private_key_b64u": B64.encode(&recovery_private_key),
        "recovery_public_key_b64u": B64.encode(&recovery_public_key),
        "recovery_policy_ref": {
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
        },
        "created_at": created_at,
    }))?;
    let body = crate::key_backup::build_did_recovery_backup_body(
        &backup_id,
        principal_id,
        device_id,
        &recovery_public_key,
        &recovery_key_ref,
        &plaintext,
        &policy.policy_id,
        policy.policy_version,
    )?;
    api.put_key_backup(&backup_id, body).await?;
    Ok(backup_id)
}

fn matching_did_recovery_backup_id(
    list_payload: &Value,
    policy: &ActiveRecoveryPolicy,
) -> Option<String> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|backup| {
            backup.get("backup_class").and_then(Value::as_str) == Some("did_recovery")
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
                    == Some(policy.policy_version)
        })
        .and_then(|backup| backup.get("backup_id").and_then(Value::as_str))
        .map(str::to_owned)
}

/// Build the `recovery-session.schema.json` `create_request` body.
pub fn create_session_body(
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    ssk_generation: u64,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<RecoverySessionCreateRequestBody> {
    Ok(RecoverySessionCreateRequestBody {
        principal_id: Did::new(principal_id.trim().to_owned())?,
        requesting_device_id: DeviceId::new(requesting_device_id.trim().to_owned())?,
        trust_domain: TypedTrustDomainId::new(trust_domain.trim().to_owned())?,
        ssk_generation,
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
    api: &CokretApi,
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    ssk_generation: u64,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<Value> {
    let body = create_session_body(
        principal_id,
        requesting_device_id,
        trust_domain,
        ssk_generation,
        expected_recovery_policy_ref,
    )?;
    api.create_recovery_session(&body).await
}

/// 6.3 — sign a `principal_signing` proof for `session` (with the principal
/// control key) and submit it. Returns the `proof_submit_response`.
pub async fn submit_principal_signing_proof(
    api: &CokretApi,
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
    api.submit_recovery_proof(session_id, &body).await
}

/// 6.3 — complete a verified session by REFERENCING the durable control events
/// the client already submitted to `POST /events`: an accepted `ck.device.authorize`
/// and `ck.device.list_update` (recovery-session.schema.json `complete_request`).
/// The server resolves + verifies each by id; it does not author control events.
pub async fn complete_recovery_session(
    api: &CokretApi,
    recovery_session_id: &str,
    authorization_event_id: &str,
    device_list_update_event_id: &str,
) -> anyhow::Result<Value> {
    let body = RecoverySessionCompleteRequestBody {
        authorization_event_id: EventId::new(authorization_event_id.trim().to_owned())?,
        device_list_update_event_id: EventId::new(device_list_update_event_id.trim().to_owned())?,
    };
    api.complete_recovery_session(recovery_session_id, &body)
        .await
}

/// 6.3 — `principal_signing` recovery driver: open session → sign + submit proof
/// → complete by referencing the already-submitted authorize + list_update event
/// ids. (Submitting those two control events to `POST /events` — the
/// SSK-signed `ck.device.authorize` + `ck.device.list_update` with the next
/// principal-control-stream actor_seq — is the caller's step; this returns the
/// `complete_response`.)
#[allow(clippy::too_many_arguments)]
pub async fn run_principal_signing_recovery(
    api: &CokretApi,
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    ssk_generation: u64,
    verification_method: &str,
    principal_signing_key: &SigningKey,
    authorization_event_id: &str,
    device_list_update_event_id: &str,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<Value> {
    let session = open_recovery_session(
        api,
        principal_id,
        requesting_device_id,
        trust_domain,
        ssk_generation,
        expected_recovery_policy_ref,
    )
    .await?;
    submit_principal_signing_proof(api, &session, verification_method, principal_signing_key)
        .await?;
    let session_id = session
        .get("recovery_session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("session missing recovery_session_id"))?;
    complete_recovery_session(
        api,
        session_id,
        authorization_event_id,
        device_list_update_event_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn create_session_body_matches_schema_shape() {
        let body = create_session_body(
            "did:web:alice.example",
            "ck:device:019a6aa0-0000-7000-8000-000000000099",
            "ck:trust_domain:soland.local",
            2,
            None,
        )
        .unwrap();
        let body = serde_json::to_value(body).unwrap();
        assert_eq!(body["principal_id"], "did:web:alice.example");
        assert_eq!(body["ssk_generation"], 2);
        assert!(body.get("expected_recovery_policy_ref").is_none());
    }

    #[test]
    fn create_session_body_includes_cas_hint() {
        let body = create_session_body(
            "did:web:alice.example",
            "ck:device:019a6aa0-0000-7000-8000-000000000099",
            "ck:trust_domain:soland.local",
            1,
            Some(("ck:policy:019a6aa0-0000-7000-8000-0000000000bb", 1)),
        )
        .unwrap();
        let body = serde_json::to_value(body).unwrap();
        assert_eq!(
            body["expected_recovery_policy_ref"]["policy_id"],
            "ck:policy:019a6aa0-0000-7000-8000-0000000000bb"
        );
        assert_eq!(body["expected_recovery_policy_ref"]["policy_version"], 1);
    }

    #[test]
    fn parse_active_policy_handles_null_and_value() {
        assert_eq!(
            parse_active_recovery_policy(&json!({ "active_policy": null })),
            None
        );
        let parsed = parse_active_recovery_policy(&json!({
            "active_policy": {
                "policy_id": "ck:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "version": 3,
                "trust_domain": "ck:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing", "recovery_unlock"],
            }
        }))
        .expect("active policy");
        assert_eq!(parsed.policy_version, 3);
        assert_eq!(
            parsed.allowed_proof_kinds,
            vec!["principal_signing", "recovery_unlock"]
        );
    }

    #[test]
    fn genesis_recovery_policy_requires_principal_scoped_signer() {
        let signer = crate::event_signer::build_ed25519_signer([7u8; 32], "did:key:zlocal");
        let err = build_signed_genesis_recovery_policy_with_signer(
            "did:webvh:zQmExample:local.host:webvh:01kv0q5a7cfrxa69d5vmtyz72f",
            "ck:trust_domain:local.host",
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
            "ck:trust_domain:local.host",
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
            "ck:trust_domain:local.host",
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
    fn account_recovery_state_requires_policy_and_did_recovery_backup() {
        let policy = json!({
            "active_policy": {
                "policy_id": "ck:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "version": 1,
                "trust_domain": "ck:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing"],
            }
        });
        let no_backup =
            account_recovery_state_from_payloads(&policy, &json!({"backups": []}), None);
        assert!(!no_backup.server_recovery_configured());

        let configured = account_recovery_state_from_payloads(
            &policy,
            &json!({
                "backups": [{
                    "backup_class": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" }
                }]
            }),
            None,
        );
        assert!(configured.server_recovery_configured());
    }

    #[test]
    fn matching_did_recovery_backup_requires_active_policy_ref() {
        let policy = ActiveRecoveryPolicy {
            policy_id: "ck:policy:019a6aa0-0000-7000-8000-0000000000bb".to_owned(),
            policy_version: 2,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            allowed_proof_kinds: vec!["recovery_unlock".to_owned()],
        };
        let payload = json!({
            "backups": [
                {
                    "backup_id": "ck:backup:019a6aa0-0000-7000-8000-000000000001",
                    "backup_class": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ck:policy:019a6aa0-0000-7000-8000-000000000000",
                        "policy_version": 2
                    }
                },
                {
                    "backup_id": "ck:backup:019a6aa0-0000-7000-8000-000000000002",
                    "backup_class": "did_recovery",
                    "encryption": { "recipient_method": "recovery_public_key" },
                    "recovery_policy_ref": {
                        "policy_id": "ck:policy:019a6aa0-0000-7000-8000-0000000000bb",
                        "policy_version": 2
                    }
                }
            ]
        });
        assert_eq!(
            matching_did_recovery_backup_id(&payload, &policy).as_deref(),
            Some("ck:backup:019a6aa0-0000-7000-8000-000000000002")
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
