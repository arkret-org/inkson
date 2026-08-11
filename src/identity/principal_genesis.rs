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

pub fn build_founding_authorize_payload(
    principal_id: arkret_sdk::DidFullId,
    device_id: arkret_sdk::DeviceId,
    device_public_key: String,
    hpke_key: String,
    created_at: DateTime<Utc>,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_sdk::DeviceAuthorizePayload> {
    let principal_core_id = arkret_sdk::project_full_id_to_core_id(&principal_id)?;
    let payload = arkret_sdk::UnsignedDeviceAuthorizePayload::new(
        principal_core_id.clone(),
        device_id,
        non_empty(device_public_key)?,
        non_empty(hpke_key)?,
        algorithms()?,
        Some(non_empty("Ed25519".to_owned())?),
        arkret_sdk::DeviceOrPrincipalRef::Principal(principal_core_id),
        None,
        created_at,
        None,
        arkret_sdk::DeviceAuthorizationBindingKind::RootAnchored,
        None,
    )?;
    let signature = signer
        .sign_raw(&payload.device_possession_signature_input()?)
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
    principal_id: arkret_sdk::DidFullId,
    genesis_salt: arkret_sdk::GenesisSalt,
    trust_domain: arkret_sdk::TypedTrustDomainId,
    did_inception_version_id: String,
    created_at: DateTime<Utc>,
    create_hlc: arkret_sdk::Hlc,
    root_seed: &[u8; 32],
    root_public_key_multibase: &str,
    device_id: arkret_sdk::DeviceId,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_wire::PcrGenesisUnit> {
    let principal_core_id = arkret_sdk::project_full_id_to_core_id(&principal_id)?;
    let payload = build_founding_authorize_payload(
        principal_id.clone(),
        device_id,
        device_public_key,
        hpke_key,
        created_at,
        device_signer,
    )?;
    let descriptor = arkret_sdk::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: payload.device_id.clone(),
        device_key_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            payload.device_public_key.as_bytes(),
        ))?,
        device_public_key: payload.device_public_key.clone(),
        device_key_algorithm: arkret_sdk::FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: arkret_sdk::FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
            payload.hpke_key.as_bytes(),
        ))?,
        hpke_key: payload.hpke_key.clone(),
        hpke_key_algorithm: arkret_sdk::FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: payload.algorithms.clone(),
        founding_authorize_payload_digest: arkret_sdk::device_authorize_payload_digest(
            &serde_json::to_value(&payload)?,
            arkret_sdk::canonical::DigestSuite::Sha256,
        )?,
    };
    descriptor.validate()?;
    let registry_digest = arkret_sdk::current_capability_action_registry_digest()
        .map_err(|error| anyhow::anyhow!("load capability action registry digest: {error}"))?;
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_core_id.clone(),
            principal_full_id: principal_id.clone(),
            genesis_salt,
            trust_domain,
            did_inception_ref: arkret_sdk::EventRef::new(
                did_inception_version_id,
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor: descriptor,
            capability_action_registry_digest: registry_digest,
            created_at,
            hlc: create_hlc,
        },
        &crate::operation::cell_write_projector,
    )?;
    let root_did = arkret_sdk::DidFullId::new(format!("did:key:{root_public_key_multibase}"))?;
    let root_method = arkret_sdk::DidUrl::new(root_did.to_string()).map_err(anyhow::Error::msg)?;
    let root_signer = arkret_sdk::Ed25519PayloadSigner::from_did_key_seed(
        *root_seed,
        root_did,
        root_method.clone(),
    );
    arkret_sdk::signatures::sign_event_with_digest_suite(
        &mut create,
        &root_signer,
        &root_method,
        arkret_sdk::canonical::DigestSuite::Sha256,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    // The PCR Realm exists only after the signed create draft has a stable
    // Event id. The authorize slot must use that exact event-derived id.
    let realm_id = create.realm_id.clone();
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_id.as_str(),
        device_signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("founding signer is not bound to a device"))?,
        realm_id.as_str(),
        root_seed,
    )?;

    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            arkret_sdk::ScopeRef::Realm { realm_id },
            principal_core_id,
            payload,
        )?
        .with_prev_refs(vec![create.event_id.clone()])
        .author(1, authorize_hlc, created_at)?;
    device_signer
        .sign_sdk_event_with_context(
            &mut authorize,
            crate::event_signer::EventProofContext::default()
                .with_digest_suite(arkret_sdk::canonical::DigestSuite::Sha256),
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    arkret_bootstrap::build_self_principal_pcr_genesis_unit(
        create,
        authorize,
        &crate::operation::cell_write_projector,
    )
    .map_err(Into::into)
}
