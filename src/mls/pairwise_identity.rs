use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const PAIRWISE_SIGNING_INFO: &[u8] = b"org.arkret.mls.minimal-metadata-pairwise-signing.v1";

pub(crate) struct PairwiseSigningMaterial {
    pub(crate) actor_id: arkret_sdk::DidCoreId,
    pub(crate) signer: std::sync::Arc<crate::event_signer::InksonEventSigner>,
    signing_seed: [u8; 32],
}

impl PairwiseSigningMaterial {
    pub(crate) fn signing_seed(&self) -> [u8; 32] {
        self.signing_seed
    }
}

pub(crate) fn derive_pairwise_signing_material(
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    realm_id: &arkret_sdk::RealmId,
) -> Result<PairwiseSigningMaterial, String> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let stored = crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
        .map_err(|error| format!("load account MLS secret for pairwise identity: {error}"))?
        .ok_or_else(|| "account MLS secret is unavailable for pairwise identity".to_owned())?;
    derive_pairwise_signing_material_from_account_secret(
        stored.secret.as_bytes(),
        authority,
        device_id,
        realm_id,
    )
}

pub(crate) fn derive_pairwise_signing_material_from_account_secret(
    account_secret: &[u8],
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    realm_id: &arkret_sdk::RealmId,
) -> Result<PairwiseSigningMaterial, String> {
    let generation = crate::identity::authoring_generation::cached_principal_authoring_generation(
        authority,
        device_id.as_str(),
    )
    .ok_or_else(|| {
        "accepted endpoint generation is unavailable for pairwise identity".to_owned()
    })?;
    if generation.authority_model
        != crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice
        || generation.authority_principal_id != authority.principal_id
    {
        return Err(
            "pairwise identity requires this endpoint's accepted device generation".to_owned(),
        );
    }
    derive_pairwise_signing_material_from_secret(
        account_secret,
        device_id,
        &generation.generation_ref,
        realm_id,
    )
}

fn derive_pairwise_signing_material_from_secret(
    account_secret: &[u8],
    device_id: &arkret_sdk::DeviceId,
    endpoint_generation_ref: &str,
    realm_id: &arkret_sdk::RealmId,
) -> Result<PairwiseSigningMaterial, String> {
    let endpoint_generation_ref = endpoint_generation_ref.trim();
    if endpoint_generation_ref.is_empty() {
        return Err("pairwise endpoint generation ref is empty".to_owned());
    }
    let transcript = arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
        "domain": "org.arkret.mls.minimal-metadata-pairwise-signing.v1",
        "realm_id": realm_id,
        "endpoint_incarnation": {
            "device_id": device_id,
            "generation_ref": endpoint_generation_ref,
        },
    }))
    .map_err(|error| format!("encode pairwise identity transcript: {error}"))?;
    let hkdf = Hkdf::<Sha256>::new(Some(PAIRWISE_SIGNING_INFO), account_secret);
    let mut signing_seed = [0_u8; 32];
    hkdf.expand(&transcript, &mut signing_seed)
        .map_err(|_| "derive pairwise signing seed".to_owned())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    let multikey =
        arkret_sdk::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
    drop(signing_key);
    let signer_did = format!("did:key:{multikey}");
    let verification_method = format!("{signer_did}#{multikey}");
    let actor_id = arkret_sdk::DidCoreId::new(format!("ak:did_core:key:{multikey}"))
        .map_err(|error| format!("derive pairwise actor id: {error}"))?;
    let signer = std::sync::Arc::new(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            signing_seed,
            signer_did,
            verification_method,
        ),
    );
    Ok(PairwiseSigningMaterial {
        actor_id,
        signer,
        signing_seed,
    })
}

#[cfg(test)]
pub(crate) fn pairwise_signing_material_for_test(
    realm_id: &arkret_sdk::RealmId,
) -> PairwiseSigningMaterial {
    derive_pairwise_signing_material_from_secret(
        b"inkson-pairwise-signing-material-test-secret",
        &arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001").unwrap(),
        "ak:event:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        realm_id,
    )
    .unwrap()
}

impl Drop for PairwiseSigningMaterial {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(seed: char) -> arkret_sdk::RealmId {
        crate::test_support::realm_id(&format!(
            "ak:realm:A{}",
            std::iter::repeat_n(seed, 43).collect::<String>()
        ))
    }

    fn device(seed: u8) -> arkret_sdk::DeviceId {
        crate::test_support::device_id(&format!("ak:device:01964137-0000-7000-8000-{seed:012x}"))
    }

    #[test]
    fn realm_and_endpoint_generation_partition_pairwise_actor() {
        let secret = b"pairwise-account-secret";
        let base = derive_pairwise_signing_material_from_secret(
            secret,
            &device(1),
            "generation-1",
            &realm('a'),
        )
        .unwrap();
        let same = derive_pairwise_signing_material_from_secret(
            secret,
            &device(1),
            "generation-1",
            &realm('a'),
        )
        .unwrap();
        let another_endpoint = derive_pairwise_signing_material_from_secret(
            secret,
            &device(2),
            "generation-1",
            &realm('a'),
        )
        .unwrap();
        let replacement = derive_pairwise_signing_material_from_secret(
            secret,
            &device(1),
            "generation-2",
            &realm('a'),
        )
        .unwrap();
        let another_realm = derive_pairwise_signing_material_from_secret(
            secret,
            &device(1),
            "generation-1",
            &realm('b'),
        )
        .unwrap();

        assert_eq!(base.actor_id, same.actor_id);
        assert_ne!(base.actor_id, another_endpoint.actor_id);
        assert_ne!(base.actor_id, replacement.actor_id);
        assert_ne!(base.actor_id, another_realm.actor_id);
        assert_ne!(base.signing_seed(), replacement.signing_seed());
    }
}
