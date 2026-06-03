//! 6.1 / 6.3 — recovery client orchestration.
//!
//! Pure request builders (unit-tested) + thin async wrappers over
//! [`crate::api::ContrixApi`] that drive the REC-1 recovery flow:
//!
//! - 6.1: fetch + parse the active recovery policy.
//! - 6.3: open a recovery session, sign + submit a `principal_signing` proof,
//!   then complete with client-supplied `cx.device.authorize` material.
//!
//! The wire shapes match `contrix-spec` `recovery-session.schema.json`
//! (`create_request` / `proof_submit_request` / `complete_request`).

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::api::ContrixApi;

/// 6.1 — parsed active recovery policy summary (the fields a client surfaces).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveRecoveryPolicy {
    pub policy_id: String,
    pub policy_version: u64,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
}

/// Parse the `GET recovery-policy` response (`{ "active_policy": <summary|null> }`)
/// into [`ActiveRecoveryPolicy`]. Returns `None` when no policy is accepted.
pub fn parse_active_recovery_policy(response: &Value) -> Option<ActiveRecoveryPolicy> {
    let p = response.get("active_policy").filter(|v| !v.is_null())?;
    Some(ActiveRecoveryPolicy {
        policy_id: p.get("policy_id").and_then(Value::as_str).unwrap_or_default().to_owned(),
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

/// 6.1 — fetch + parse the active recovery policy.
pub async fn fetch_active_recovery_policy(
    api: &ContrixApi,
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
    api: &ContrixApi,
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
    api: &ContrixApi,
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

/// 6.3 — complete a verified session with client-supplied, SSK-signed
/// `cx.device.authorize` material. `device_authorize` MUST satisfy
/// `recovery-session.schema.json` `$defs/device_authorize_material`.
pub async fn complete_recovery_session(
    api: &ContrixApi,
    recovery_session_id: &str,
    device_authorize: Value,
) -> anyhow::Result<Value> {
    api.complete_recovery_session(
        recovery_session_id,
        json!({ "device_authorize": device_authorize }),
    )
    .await
}

/// 6.3 — end-to-end `principal_signing` recovery driver: open session → sign +
/// submit proof → complete. `device_authorize` is the client's SSK-signed
/// device-authorization material (built from the SSK unlocked during the
/// fresh-device restore). Returns the `complete_response`.
#[allow(clippy::too_many_arguments)]
pub async fn run_principal_signing_recovery(
    api: &ContrixApi,
    principal_id: &str,
    requesting_device_id: &str,
    trust_domain: &str,
    ssk_generation: u64,
    verification_method: &str,
    principal_signing_key: &SigningKey,
    device_authorize: Value,
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
    complete_recovery_session(api, session_id, device_authorize).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session_body_matches_schema_shape() {
        let body = create_session_body(
            "did:web:alice.example",
            "cx:device:019a6aa0-0000-7000-8000-000000000099",
            "cx:trust_domain:soland.local",
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
            "cx:device:019a6aa0-0000-7000-8000-000000000099",
            "cx:trust_domain:soland.local",
            1,
            Some(("cx:policy:019a6aa0-0000-7000-8000-0000000000bb", 1)),
        );
        assert_eq!(
            body["expected_recovery_policy_ref"]["policy_id"],
            "cx:policy:019a6aa0-0000-7000-8000-0000000000bb"
        );
        assert_eq!(body["expected_recovery_policy_ref"]["policy_version"], 1);
    }

    #[test]
    fn parse_active_policy_handles_null_and_value() {
        assert_eq!(parse_active_recovery_policy(&json!({ "active_policy": null })), None);
        let parsed = parse_active_recovery_policy(&json!({
            "active_policy": {
                "policy_id": "cx:policy:019a6aa0-0000-7000-8000-0000000000bb",
                "version": 3,
                "trust_domain": "cx:trust_domain:soland.local",
                "allowed_proof_kinds": ["principal_signing", "recovery_unlock"],
            }
        }))
        .expect("active policy");
        assert_eq!(parsed.policy_version, 3);
        assert_eq!(parsed.allowed_proof_kinds, vec!["principal_signing", "recovery_unlock"]);
    }
}
