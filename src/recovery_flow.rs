//! 6.1 / 6.3 — recovery client orchestration.
//!
//! Pure request builders (unit-tested) + thin async wrappers over
//! [`crate::api::CokretApi`] that drive the REC-1 recovery flow:
//!
//! - 6.1: fetch + parse the active recovery policy.
//! - 6.3: open a recovery session, sign + submit a `principal_signing` proof, then complete with
//!   client-supplied `ck.device.authorize` material.
//!
//! The wire shapes match `cokret-spec` `recovery-session.schema.json`
//! (`create_request` / `proof_submit_request` / `complete_request`).

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::api::CokretApi;

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

/// Build the `recovery-session.schema.json` `create_request` body.
pub fn create_session_body(
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    ssk_generation: u64,
    expected_recovery_policy_ref: Option<(&str, u64)>,
) -> Value {
    let mut body = json!({
        "principal_id": principal_id,
        "requesting_device_id": requesting_device_id,
        "trust_domain": trust_domain,
        "ssk_generation": ssk_generation,
    });
    if let Some((policy_id, policy_version)) = expected_recovery_policy_ref {
        body["expected_recovery_policy_ref"] =
            json!({ "policy_id": policy_id, "policy_version": policy_version });
    }
    body
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
    );
    api.create_recovery_session(body).await
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
    api.submit_recovery_proof(session_id, json!({ "proof": proof }))
        .await
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
    api.complete_recovery_session(
        recovery_session_id,
        json!({
            "authorization_event_id": authorization_event_id,
            "device_list_update_event_id": device_list_update_event_id,
        }),
    )
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
    use super::*;

    #[test]
    fn create_session_body_matches_schema_shape() {
        let body = create_session_body(
            "did:web:alice.example",
            "ck:device:019a6aa0-0000-7000-8000-000000000099",
            "ck:trust_domain:soland.local",
            2,
            None,
        );
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
        );
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
