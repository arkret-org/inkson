//! Client-authored principal registration and resumable bootstrap checkpoint.

use anyhow::{Context as _, anyhow};
use chrono::{SecondsFormat, Timelike as _, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::identity::account_auth::AuthorityResolver;
use crate::state::{PendingPrincipalRegistration, PendingPrincipalRegistrationStage};
use crate::transport::TransportClient;

const WEBVH_REGISTRATION_PATH: &str = "/_coauth/account/auth/register/webvh";

#[derive(Clone, Debug)]
pub struct RegistrationStart {
    pub principal_server_url: String,
    pub gate_account_base: String,
    pub registration_id: String,
    pub enrollment_authority_did: String,
    pub trust_domain: String,
}

#[derive(Clone, Debug)]
pub struct RegistrationEmailSent {
    pub dev_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StartOutcome {
    status: String,
    registration_id: Option<String>,
    enrollment_authority_did: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailOutcome {
    status: String,
    dev_code: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StepOutcome {
    status: String,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FinishOutcome {
    status: String,
    error: Option<String>,
}

#[derive(Serialize)]
struct StartRequest<'a> {
    handle: &'a str,
    principal_server_url: &'a str,
}

fn registration_url(gate_account_base: &str, suffix: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(gate_account_base.trim())
        .context("invalid Account Authority gate_account_base")?;
    if matches!(url.origin(), url::Origin::Opaque(_)) {
        anyhow::bail!("Account Authority gate_account_base has no HTTPS origin");
    }
    url.set_path(&format!("{WEBVH_REGISTRATION_PATH}{suffix}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

async fn post_json<T: DeserializeOwned>(url: Url, body: &impl Serialize) -> anyhow::Result<T> {
    let response = reqwest::Client::new()
        .post(url)
        .json(body)
        .send()
        .await
        .context("Account Authority registration request failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("read Account Authority registration response")?;
    if !status.is_success() {
        let message = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        value
                            .get("error")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
            })
            .unwrap_or_else(|| format!("HTTP {status}"));
        anyhow::bail!("Account Authority registration failed: {message}");
    }
    serde_json::from_slice(&bytes).context("decode Account Authority registration response")
}

pub async fn start_registration(
    principal_server_url: &str,
    handle: &str,
) -> anyhow::Result<RegistrationStart> {
    let principal_server_url = crate::config::normalize_server_url(principal_server_url);
    let principal = TransportClient::unauthenticated(&principal_server_url)
        .context("invalid Principal Server URL")?;
    let description = principal
        .describe()
        .await
        .context("Principal Server discovery failed")?;
    let resolver = AuthorityResolver::from_description(&principal_server_url, &description)
        .context("Account Authority discovery failed")?;
    let outcome: StartOutcome = post_json(
        registration_url(&resolver.gate_account_base, "/start")?,
        &StartRequest {
            handle: handle.trim(),
            principal_server_url: &principal_server_url,
        },
    )
    .await?;
    if outcome.status != "success" {
        anyhow::bail!(
            "{}",
            outcome
                .error
                .unwrap_or_else(|| "registration_start_failed".to_owned())
        );
    }
    Ok(RegistrationStart {
        principal_server_url,
        gate_account_base: resolver.gate_account_base,
        registration_id: outcome
            .registration_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("registration start omitted registration_id"))?,
        enrollment_authority_did: outcome
            .enrollment_authority_did
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("registration start omitted enrollment authority DID"))?,
        trust_domain: description.trust_domain.to_string(),
    })
}

pub async fn send_registration_email(
    start: &RegistrationStart,
    email: &str,
) -> anyhow::Result<RegistrationEmailSent> {
    let suffix = format!("/{}/email", start.registration_id);
    let outcome: EmailOutcome = post_json(
        registration_url(&start.gate_account_base, &suffix)?,
        &serde_json::json!({ "email": email.trim() }),
    )
    .await?;
    if outcome.status != "sent" {
        anyhow::bail!(
            "{}",
            outcome
                .error
                .unwrap_or_else(|| "registration_email_failed".to_owned())
        );
    }
    Ok(RegistrationEmailSent {
        dev_code: outcome.dev_code,
    })
}

pub async fn verify_registration_email(
    start: &RegistrationStart,
    code: &str,
) -> anyhow::Result<()> {
    let suffix = format!("/{}/verify-email", start.registration_id);
    let outcome: StepOutcome = post_json(
        registration_url(&start.gate_account_base, &suffix)?,
        &serde_json::json!({ "code": code.trim() }),
    )
    .await?;
    if outcome.status != "success" {
        anyhow::bail!(
            "{}",
            outcome
                .error
                .unwrap_or_else(|| "email_verification_failed".to_owned())
        );
    }
    Ok(())
}

pub fn prepare_registration_checkpoint(
    start: &RegistrationStart,
    handle: &str,
    email: &str,
    device_id: &str,
    recovery_key: &str,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    let endpoint = Url::parse(&start.principal_server_url)
        .context("Principal Server URL cannot drive did:webvh inception")?;
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);
    let local_id = start.registration_id.trim().to_ascii_lowercase();
    let draft = arkret_sdk::webvh::prepare_principal_inception(
        &arkret_sdk::webvh::PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
            enrollment: arkret_sdk::webvh::PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: &start.enrollment_authority_did,
            },
        },
    )?;
    let bootstrap_create_event_id = arkret_sdk::identifiers::new_prefixed_uuid7("ak:event:");
    arkret_sdk::EventId::new(bootstrap_create_event_id.clone())?;
    let draft_actor = arkret_sdk::Did::new(draft.did.clone())?;
    let draft_realm = arkret_sdk::principal_control_realm_id(&draft_actor);
    let bootstrap_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        draft_actor.as_str(),
        device_id.trim(),
        &draft_realm,
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        principal_server_url: start.principal_server_url.clone(),
        gate_account_base: start.gate_account_base.clone(),
        registration_id: start.registration_id.clone(),
        handle: handle.trim().to_owned(),
        email: email.trim().to_owned(),
        device_id: device_id.trim().to_owned(),
        enrollment_authority_did: start.enrollment_authority_did.clone(),
        trust_domain: start.trust_domain.clone(),
        did: draft.did,
        version_id: draft.version_id,
        root_public_key_multibase: draft.root_public_key_multibase,
        root_verification_method: draft.root_verification_method,
        next_root_public_key_multibase: draft.next_root_public_key_multibase,
        next_root_key_hash: draft.next_root_key_hash,
        recovery_proof_public_key_multibase: key_material
            .recovery_proof_public_key_multikey
            .clone(),
        backup_hpke_public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
        recovery_key_fingerprint: crate::recovery_crypto::fingerprint_recovery_key(recovery_key),
        did_operation: serde_json::to_value(draft.submit_body)?,
        bootstrap_create_event_id,
        bootstrap_created_at: created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        bootstrap_hlc,
        stage: PendingPrincipalRegistrationStage::CustodyConfirmed,
    })
}

pub async fn finish_registration(
    checkpoint: &PendingPrincipalRegistration,
    password: &str,
    password_confirm: &str,
) -> anyhow::Result<()> {
    let suffix = format!("/{}/finish", checkpoint.registration_id);
    let outcome: FinishOutcome = post_json(
        registration_url(&checkpoint.gate_account_base, &suffix)?,
        &serde_json::json!({
            "did_operation": checkpoint.did_operation,
            "password": password,
            "password_confirm": password_confirm,
        }),
    )
    .await?;
    if outcome.status != "success" {
        anyhow::bail!(
            "{}",
            outcome
                .error
                .unwrap_or_else(|| "registration_finish_failed".to_owned())
        );
    }
    Ok(())
}

pub fn registration_start_from_checkpoint(
    checkpoint: &PendingPrincipalRegistration,
) -> RegistrationStart {
    RegistrationStart {
        principal_server_url: checkpoint.principal_server_url.clone(),
        gate_account_base: checkpoint.gate_account_base.clone(),
        registration_id: checkpoint.registration_id.clone(),
        enrollment_authority_did: checkpoint.enrollment_authority_did.clone(),
        trust_domain: checkpoint.trust_domain.clone(),
    }
}

pub fn validate_checkpoint_recovery_key(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
) -> anyhow::Result<arkret_sdk::identity_root::IdentityRecoveryKeyMaterial> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    let fingerprint = crate::recovery_crypto::fingerprint_recovery_key(recovery_key);
    if checkpoint.recovery_key_fingerprint != fingerprint
        || checkpoint.root_public_key_multibase != key_material.root_public_key_multikey
        || checkpoint.next_root_public_key_multibase != key_material.next_root_public_key_multikey
        || checkpoint.next_root_key_hash != key_material.next_root_key_hash
        || checkpoint.recovery_proof_public_key_multibase
            != key_material.recovery_proof_public_key_multikey
        || checkpoint.backup_hpke_public_key_multibase
            != key_material.backup_hpke_public_key_multikey
    {
        anyhow::bail!("Recovery Key does not match the persisted identity draft");
    }
    Ok(key_material)
}

pub async fn bootstrap_principal(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
    account_client: &arkret_sdk::http_client::Client,
    principal_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let realm_id = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.bootstrap_created_at)
        .context("persisted bootstrap_created_at is invalid")?
        .with_timezone(&Utc);
    let mut create = arkret_sdk::identity::build_self_principal_pcr_create(
        arkret_sdk::identity::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            realm_id: realm_id.clone(),
            trust_domain: arkret_sdk::TypedTrustDomainId::new(checkpoint.trust_domain.clone())?,
            did_inception_ref: arkret_sdk::EventRef::new(
                checkpoint.version_id.clone(),
                arkret_sdk::identity::DID_INCEPTION_REF_ROLE,
            ),
            event_id: arkret_sdk::EventId::new(checkpoint.bootstrap_create_event_id.clone())?,
            created_at,
            hlc: arkret_sdk::Hlc::new(checkpoint.bootstrap_hlc.clone())?,
        },
    )?;
    let root_did =
        arkret_sdk::Did::new(format!("did:key:{}", checkpoint.root_public_key_multibase))?;
    let root_signer = arkret_sdk::Ed25519MoveSigner::from_did_key_seed(
        key_material.root_seed,
        root_did,
        checkpoint.root_verification_method.clone(),
    );
    arkret_sdk::signatures::sign_event(
        &mut create,
        &root_signer,
        &checkpoint.root_verification_method,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    let request = crate::identity::device_enrollment::DeviceEnrollmentRequest {
        device_id: checkpoint.device_id.clone(),
        device_public_key,
        actor_seq: 1,
        bootstrap_create_event_id: Some(create.event_id.to_string()),
        not_before: None,
        hpke_key,
        algorithms: crate::identity::device_enrollment::inkson_device_algorithms(),
    };
    let authorize = crate::identity::device_enrollment::request_signed_device_authorize(
        account_client,
        &request,
        &checkpoint.device_id,
    )
    .await?;
    let seal_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_id.as_str(),
        &checkpoint.device_id,
        realm_id.as_str(),
        &key_material.root_seed,
    )?;
    let seal = device_signer
        .sign_self_principal_bootstrap_seal(&create, &authorize, seal_hlc)
        .map_err(|error| anyhow!(error.to_string()))?;
    let expected_digests = seal.delta.clone();
    let batch = arkret_sdk::identity::self_principal_bootstrap_submit_request(create, authorize)?;
    let response = principal_client.events_submit_batch(&batch.events).await?;
    crate::ephemeral::ensure_events_submit_accepted(&response)?;
    let seal_outcome = principal_client.events_submit_seal(&seal).await?;
    if seal_outcome.seal_id != seal.id
        || seal_outcome.accepted_event_digests != expected_digests
        || seal_outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched bootstrap Seal outcome");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_registration_url_uses_only_the_discovered_authority_origin() {
        assert_eq!(
            registration_url(
                "https://auth.example/_arkret/gate/account",
                "/01test/finish"
            )
            .unwrap()
            .as_str(),
            "https://auth.example/_coauth/account/auth/register/webvh/01test/finish"
        );
    }

    #[test]
    fn persisted_checkpoint_contains_no_recovery_secret_and_requires_the_same_key() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let start = RegistrationStart {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            registration_id: "01JTESTREGISTRATION0000000000".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            trust_domain: "ak:trust-domain:test".to_owned(),
        };
        let checkpoint = prepare_registration_checkpoint(
            &start,
            "alice",
            "alice@example.test",
            "ak:device:019f0000-0000-7000-8000-000000000001",
            &recovery_key,
        )
        .unwrap();

        let persisted = serde_json::to_string(&checkpoint).unwrap();
        for word in recovery_key.split_whitespace() {
            assert!(!persisted.contains(word));
        }
        assert!(!persisted.contains("root_seed"));
        assert!(!persisted.contains("recovery_proof_seed"));
        assert!(!persisted.contains("backup_hpke_private"));
        validate_checkpoint_recovery_key(&checkpoint, &recovery_key).unwrap();

        let another_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        assert!(validate_checkpoint_recovery_key(&checkpoint, &another_key).is_err());
    }
}
