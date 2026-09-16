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

fn decode_founding_device_public_key(device_public_key: &str) -> anyhow::Result<[u8; 32]> {
    let public_key_multibase = device_public_key
        .strip_prefix("did:key:")
        .ok_or_else(|| anyhow::anyhow!("founding device public key must be a did:key"))?;
    arkret_sdk::decode_ed25519_multibase(public_key_multibase)
        .map_err(|error| anyhow::anyhow!("decode founding device public key: {error}"))
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
    let payload = arkret_sdk::UnsignedDeviceAuthorizePayload::new(
        device_id,
        non_empty(device_public_key)?,
        non_empty(hpke_key)?,
        algorithms()?,
        Some(non_empty("Ed25519".to_owned())?),
        arkret_sdk::DeviceOrPrincipalRef::Principal(principal_id),
        None,
        created_at,
        None,
        arkret_sdk::DeviceAuthorizationBindingKind::RegistrationAnchor,
        None,
        None,
    )?;
    let signature = signer
        .sign_raw(&payload.device_possession_signature_input(&account_id)?)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    payload
        .attach_signature(
            arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
                .map_err(anyhow::Error::msg)?,
        )
        .map_err(anyhow::Error::from)
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
    create_hlc: arkret_sdk::Hlc,
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
    let founding_notary_public_key =
        decode_founding_device_public_key(payload.device_public_key_did.as_str())?;
    let founding_notary = arkret_sdk::NotaryValue::new(
        arkret_sdk::NotarySignerDescriptor {
            actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal_id.clone(),
                station_id.clone(),
            )),
            verification_method: arkret_sdk::DidUrl::new(format!(
                "{}#{}",
                principal_did, payload.device_id
            ))
            .map_err(anyhow::Error::msg)?,
            key_kind: arkret_sdk::NotaryKeyKind::Ed25519Raw32,
            jose_algorithm: arkret_sdk::NotaryJoseAlgorithm::Ed25519,
            frozen_public_key_b64u: arkret_sdk::base64url_encode(founding_notary_public_key),
        },
        1_000,
    )?;
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            station_id,
            principal_did: principal_did.clone(),
            notary: founding_notary,
            genesis_salt,
            trust_domain,
            did_inception_ref: arkret_sdk::EventRef::new(
                did_inception_version_id.clone(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            initial_resolution: arkret_sdk::ResolutionCommitment {
                did: principal_did.clone(),
                method_history_head: did_inception_log_head,
                version_id: did_inception_version_id,
            },
            founding_device_descriptor: descriptor,
            created_at,
            hlc: create_hlc,
        },
        &|event| crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256),
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
        &root_method,
        arkret_sdk::signatures::SignEventOptions::for_native_unit().with_created_at(created_at),
    )?;

    // The PCR Realm exists only after the signed create draft has a stable
    // Event id. The authorize slot must use that exact event-derived id.
    let realm_id = create.realm_id.clone();
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_did.as_str(),
        device_signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("founding signer is not bound to a device"))?,
        realm_id.as_str(),
        root_seed,
    )?;

    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            arkret_sdk::ScopeRef::Realm { realm_id },
            create.actor_id.clone(),
            payload,
        )?
        .with_prev_refs(vec![create.event_id().clone()])
        .author_with_digest_suite(
            1,
            authorize_hlc,
            created_at,
            arkret_sdk::canonical::DigestSuite::Sha256,
        )?;
    device_signer
        .sign_sdk_event_with_context_at(
            &mut authorize,
            crate::event_signer::ProducerProofContext::for_native_unit(
                arkret_sdk::canonical::DigestSuite::Sha256,
            ),
            created_at,
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    arkret_bootstrap::build_self_principal_pcr_genesis_unit(
        create.into_event(),
        authorize.into_event(),
        &|event| crate::operation::cell_write_projector(event, arkret_sdk::DigestSuite::Sha256),
    )
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
    fn founding_device_public_key_decodes_did_key_ed25519_material() {
        let expected = [7_u8; 32];
        let multibase = arkret_sdk::ed25519_pubkey_to_did_key_multibase(&expected);

        assert_eq!(
            decode_founding_device_public_key(&format!("did:key:{multibase}")).unwrap(),
            expected
        );
    }

    #[test]
    fn founding_device_public_key_rejects_non_did_key_input() {
        let error = decode_founding_device_public_key("not-a-did-key").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("founding device public key must be a did:key")
        );
    }
}
