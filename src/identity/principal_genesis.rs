//! Client-owned construction of the complete two-Event PCR genesis unit.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};

pub const INKSON_DEVICE_ALGORITHMS: &[&str] = &["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"];

fn non_empty(value: String) -> anyhow::Result<arkret_sdk::NonEmptyString> {
    arkret_sdk::NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

fn algorithms() -> anyhow::Result<Vec<arkret_sdk::NonEmptyString>> {
    INKSON_DEVICE_ALGORITHMS
        .iter()
        .map(|value| non_empty((*value).to_owned()))
        .collect()
}

fn did_key_verification_method(public_key_multibase: &str) -> anyhow::Result<arkret_sdk::DidUrl> {
    arkret_sdk::DidUrl::new(format!(
        "did:key:{public_key_multibase}#{public_key_multibase}"
    ))
    .map_err(anyhow::Error::msg)
}

pub fn build_founding_authorize_payload(
    principal_did: arkret_sdk::Did,
    station_id: arkret_sdk::DidCoreId,
    device_id: arkret_sdk::DeviceId,
    device_public_key: String,
    hpke_key: String,
    created_at: DateTime<Utc>,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_sdk::DeviceAuthorizePayload> {
    let principal_id = arkret_sdk::project_did_to_core_id(&principal_did)?;
    let account_id = arkret_sdk::AccountId::new(principal_id.clone(), station_id);
    // `device_signature` is excluded from its own possession transcript. Keep
    // the temporary material private to this function, replace it immediately,
    // and only return the fully signed canonical payload.
    let mut payload = arkret_sdk::DeviceAuthorizePayload {
        device_id,
        device_public_key_did: non_empty(device_public_key)?,
        hpke_key: non_empty(hpke_key)?,
        algorithms: algorithms()?,
        device_key_algorithm: non_empty("Ed25519".to_owned())?,
        authorized_by: arkret_sdk::DeviceOrPrincipalRef::Principal(principal_id),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: arkret_sdk::DeviceAuthorizationBindingKind::RegistrationAnchor,
        authorized_generation_ref: 1,
        device_signature: arkret_sdk::SignatureMaterial::NonEmptyString(non_empty(
            "pending".to_owned(),
        )?),
        recovery_session_id: None,
        pairing_challenge_transcript_digest: None,
        applet_id: None,
    };
    payload
        .validate_wire_constraints()
        .map_err(anyhow::Error::msg)?;
    let signature = signer
        .sign_raw(&payload.device_possession_signature_input(&account_id)?)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let signature = arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
        .map_err(anyhow::Error::msg)?;
    payload.device_signature =
        arkret_sdk::SignatureMaterial::NonEmptyString(non_empty(signature.into_string())?);
    payload
        .validate_wire_constraints()
        .map_err(anyhow::Error::msg)?;
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
pub fn build_genesis_unit(
    principal_did: arkret_sdk::Did,
    station_id: arkret_sdk::DidCoreId,
    genesis_salt: arkret_sdk::GenesisSalt,
    trust_domain: arkret_sdk::TrustDomainId,
    did_inception_version_id: String,
    did_inception_log_head: String,
    created_at: DateTime<Utc>,
    root_seed: &[u8; 32],
    root_public_key_multibase: &str,
    device_id: arkret_sdk::DeviceId,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_wire::PcrGenesisUnit> {
    let principal_id = arkret_sdk::project_did_to_core_id(&principal_did)?;
    let payload = build_founding_authorize_payload(
        principal_did.clone(),
        station_id.clone(),
        device_id,
        device_public_key,
        hpke_key,
        created_at,
        device_signer,
    )?;
    let descriptor = arkret_sdk::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: payload.device_id.clone(),
        device_public_key_did: payload.device_public_key_did.clone(),
        device_key_algorithm: arkret_sdk::FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: arkret_sdk::FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key: payload.hpke_key.clone(),
        hpke_key_algorithm: arkret_sdk::FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: payload.algorithms.clone(),
        founding_authorize_payload_digest: arkret_sdk::device_authorize_payload_digest(
            &serde_json::to_value(&payload)?,
            arkret_sdk::canonical::DigestSuite::Sha256,
        )?,
    };
    descriptor.validate()?;
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            governance_station_id: station_id,
            principal_did: principal_did.clone(),
            genesis_salt,
            trust_domain,
            did_inception_ref: arkret_sdk::SemanticRef::new(
                did_inception_version_id.clone(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            initial_resolution: arkret_sdk::ResolutionCommitment {
                did: principal_did.clone(),
                method_history_head: did_inception_log_head,
                version_id: did_inception_version_id,
            },
            founding_device_descriptor: descriptor,
            initial_join_rule: arkret_sdk::JoinRule::Closed,
            initial_history_access: arkret_sdk::HistoryAccess::SinceJoin,
            initial_discoverability: arkret_sdk::Discoverability::Secret,
            created_at,
        },
    )?;
    let root_did = arkret_sdk::Did::new(format!("did:key:{root_public_key_multibase}"))?;
    let root_method = did_key_verification_method(root_public_key_multibase)?;
    let root_signer = arkret_sdk::Ed25519PayloadSigner::from_did_key_seed(
        *root_seed,
        root_did,
        root_method.clone(),
    );
    arkret_sdk::signatures::sign_event(
        &mut create,
        &root_signer,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    // The PCR Realm exists only after the signed create draft has a stable
    // Event id. The authorize slot must use that exact event-derived id.
    let realm_id = create.realm_id.clone();
    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            arkret_sdk::ScopeRef::Realm { realm_id },
            create.actor_id.clone(),
            payload,
        )?
        .author_with_digest_suite(created_at, arkret_sdk::canonical::DigestSuite::Sha256)?;
    device_signer
        .sign_sdk_event_with_context_at(
            &mut authorize,
            crate::event_signer::ProducerProofContext::for_native_unit(
                arkret_sdk::canonical::DigestSuite::Sha256,
            ),
            created_at,
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    arkret_bootstrap::build_pcr_genesis_unit(create.into_event(), authorize.into_event())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_verification_method_repeats_multibase_key_as_fragment() {
        let key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

        assert_eq!(
            did_key_verification_method(key).unwrap().as_str(),
            format!("did:key:{key}#{key}")
        );
    }

    #[test]
    fn founding_authorization_binds_generation_one() {
        let principal = arkret_sdk::Did::new("did:webvh:z6mkfixture:principal.example").unwrap();
        let signer = crate::event_signer::build_ed25519_signer([7_u8; 32], principal.as_str());
        let payload = build_founding_authorize_payload(
            principal,
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap(),
            "did:key:z6Mki3devicepublickey".to_owned(),
            "z6LSdevicehpke".to_owned(),
            "2026-09-20T00:00:00Z".parse().unwrap(),
            &signer,
        )
        .unwrap();

        assert_eq!(payload.authorized_generation_ref, 1);
        assert_eq!(
            serde_json::to_value(payload).unwrap()["authorized_generation_ref"],
            serde_json::json!(1)
        );
    }
}
