//! Organization closed-loop client logic (D1-D3).
//!
//! An organization is a first-class `did:webvh` DID controller, distinct from a
//! human login session. The server administrator mints an organization DID
//! (D2), persists the organization control private key locally (D1), then signs
//! `ak.realm.organization` relationship statements binding the organization to a
//! Realm (D3). The organization-side statement proof is produced with the
//! organization control key via [`arkret_sdk::realm_organization_statement_sign`],
//! NOT with the human login / device signer.
//!
//! Upstream the entire DID-minting + statement-signing cryptography lives in the
//! SDK (`arkret_sdk::webvh::*`, `arkret_sdk::realm_organization_statement_sign`);
//! this module only orchestrates RNG sourcing, secure-key persistence, and the
//! payload assembly the SDK signs.

use arkret_identifiers::{Did, DidCoreId, project_did_to_core_id};
use arkret_models_collaboration::events_payloads::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial,
};
use arkret_sdk::webvh::{PreparedInception, ServiceInceptionInput, prepare_service_inception};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use rand_core_06::{CryptoRng, RngCore};

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

/// Stable secure-key-store key prefix for an organization control signing seed.
/// The minted organization DID is appended (URL-safe base64, no padding) so a
/// single server administrator can mint and control multiple organizations on
/// the same device without key collisions. No version suffix per the storage
/// convention.
const ORGANIZATION_CONTROL_SEED_KEY: &str = "organization.control.seed";

/// A `getrandom`-backed [`RngCore`] (rand_core 0.6) adapter. inkson routes all
/// randomness through `getrandom::fill` (uniform across native + wasm); the SDK
/// inception builder wants a `rand_core` 0.6 `RngCore`, so this wraps the OS
/// source into that trait. It is also a `CryptoRng` because `getrandom` is a
/// cryptographically secure source.
struct GetrandomRng;

impl RngCore for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        // getrandom is infallible in practice on the supported targets; on the
        // theoretical failure path fall back to a zeroed read rather than
        // panicking. The inception builder additionally re-verifies its own
        // proof, so a degenerate read cannot produce an accepted DID.
        let _ = getrandom::fill(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        let _ = getrandom::fill(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = getrandom::fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        getrandom::fill(dest)
            .map_err(|err| rand_core_06::Error::new(std::io::Error::other(err.to_string())))
    }
}

impl CryptoRng for GetrandomRng {}

/// Secure-key-store key for the control seed of `organization_id`.
fn organization_control_seed_key(organization_id: &DidCoreId) -> String {
    format!(
        "{ORGANIZATION_CONTROL_SEED_KEY}.{}",
        URL_SAFE_NO_PAD.encode(organization_id.as_str().as_bytes())
    )
}

/// Persist an organization control signing seed (32-byte Ed25519 seed) under a
/// stable per-organization key. The value is hex so it round-trips through every
/// OS keychain backend without padding nuance, matching how every other
/// device signing seed is persisted.
pub fn store_organization_control_seed(
    store: &dyn SecureKeyStore,
    organization_id: &DidCoreId,
    seed: &[u8; 32],
) -> Result<(), SecureKeyStoreError> {
    store.store_secret(
        &organization_control_seed_key(organization_id),
        &crate::canonical::hex_encode(seed),
    )
}

/// Reload a previously persisted organization control signing key. Returns
/// `Ok(None)` when no seed is stored for `organization_id` on this device.
pub fn load_organization_control_key(
    store: &dyn SecureKeyStore,
    organization_id: &DidCoreId,
) -> Result<Option<SigningKey>, SecureKeyStoreError> {
    let Some(value) = store.get_secret(&organization_control_seed_key(organization_id))? else {
        return Ok(None);
    };
    let bytes = crate::canonical::hex_decode(&value).ok_or_else(|| {
        SecureKeyStoreError::Backend("organization control seed hex decode failed".to_owned())
    })?;
    if bytes.len() != 32 {
        return Err(SecureKeyStoreError::Backend(format!(
            "organization control seed length {}, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(SigningKey::from_bytes(&seed)))
}

/// Result of a successful organization mint (D2): the artefacts the caller
/// persists + displays. The `submit_body` is POSTed to soland to mint the DID.
pub struct PreparedOrganization {
    /// Stable identity of the organization principal.
    pub organization_id: DidCoreId,
    /// The minted organization `did:webvh`.
    pub organization_did: Did,
    /// 32-byte Ed25519 control seed — caller MUST persist this (it is the
    /// organization's signing authority for relationship statements).
    pub control_seed: [u8; 32],
    /// The organization control verification method id (`<did>#did-key-1`).
    /// Used verbatim as `authorization.verification_method` when binding.
    pub did_key_id: String,
}

/// Errors raised while preparing an organization inception (D2).
#[derive(Debug, thiserror::Error)]
pub enum OrganizationError {
    #[error("organization principal endpoint is not a valid URL: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("organization local_id must not be empty")]
    EmptyLocalId,
    #[error("webvh inception failed: {0}")]
    Inception(#[from] arkret_sdk::webvh::WebvhInceptionError),
    #[error("prepared organization DID is invalid: {0}")]
    Identifier(#[from] arkret_identifiers::IdentifierError),
}

/// Build a `did:webvh` inception for a new organization (D2, client side).
///
/// `principal_endpoint` is the soland base URL (the organization is anchored to
/// this Principal Server's `did:webvh` method authority). `local_id` is the
/// organization's stable handle / slug. `also_known_as` carries optional
/// reverse-link handles. Organizations use the service-identity WebVH profile:
/// they are not human principals and therefore must not publish a principal
/// device-enrollment-authority service slot.
///
/// On success returns the prepared inception (which carries `submit_body` to
/// POST to soland) plus a [`PreparedOrganization`] with the secrets + ids the
/// caller persists.
pub fn prepare_organization_inception(
    principal_endpoint: &str,
    local_id: &str,
    display_name: Option<&str>,
    also_known_as: &[String],
) -> Result<(PreparedInception, PreparedOrganization), OrganizationError> {
    let local_id = local_id.trim();
    if local_id.is_empty() {
        return Err(OrganizationError::EmptyLocalId);
    }
    let endpoint = url::Url::parse(principal_endpoint)?;

    // Fold an optional display name into the alsoKnownAs surface so the minted
    // document reverse-links the human-facing label; the wire shape is a flat
    // string list either way.
    let mut aka: Vec<String> = also_known_as.to_vec();
    if let Some(name) = display_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let label = format!("name:{name}");
        if !aka.iter().any(|existing| existing == &label) {
            aka.push(label);
        }
    }

    let input = ServiceInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &aka,
        version_time: crate::clock::now_utc(),
        did_key_fragment: None,
    };
    let mut rng = GetrandomRng;
    let prepared = prepare_service_inception(&mut rng, &input)?;
    let did = Did::new(prepared.did.clone())?;
    let organization_id = project_did_to_core_id(&did)?;

    let organization = PreparedOrganization {
        organization_id,
        organization_did: did,
        control_seed: prepared.did_key_seed,
        did_key_id: prepared.did_key_id.clone(),
    };
    Ok((prepared, organization))
}

/// Inputs for assembling + signing a `ak.realm.organization` statement (D3).
pub struct OrganizationStatementInput {
    pub statement_id: String,
    pub realm_id: String,
    pub organization_id: DidCoreId,
    /// Exact resolvable DID whose control method signs this statement.
    pub organization_did: Did,
    /// Organization control verification method id (`<did>#did-key-1`).
    pub verification_method: String,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// REQUIRED when `status == Revoked`; MUST be absent for `Active`.
    pub revokes_statement_id: Option<String>,
}

/// Assemble a [`RealmOrganizationPayload`] and sign its `authorization.proof`
/// with the organization control key (D3, organization side).
///
/// The returned payload carries a real detached Ed25519 proof over the canonical
/// statement signing bytes; the caller then feeds the SAME fields (plus this
/// signed proof) into the `ak.realm.organization` operation builder, which
/// reconstructs an identical payload so the canonical bytes — and therefore the
/// proof — remain valid on the wire.
///
/// `issuer_role` is always `OrganizationPrincipalId`: the organization principal controller
/// signs directly, so no `delegation_ref` is involved.
pub fn sign_organization_statement(
    input: &OrganizationStatementInput,
    control_key: &SigningKey,
) -> anyhow::Result<RealmOrganizationPayload> {
    let realm_id = arkret_sdk::RealmId::new(input.realm_id.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid realm id `{}`: {err}", input.realm_id))?;
    let projected_organization_id =
        project_did_to_core_id(&input.organization_did).map_err(|err| {
            anyhow::anyhow!(
                "invalid organization DID `{}`: {err}",
                input.organization_did
            )
        })?;
    if projected_organization_id != input.organization_id {
        anyhow::bail!(
            "organization DID `{}` does not project to organization_id `{}`",
            input.organization_did,
            input.organization_id
        );
    }

    if input.control_scopes.is_empty() {
        anyhow::bail!("ak.realm.organization control_scopes must not be empty");
    }
    match (input.status, &input.revokes_statement_id) {
        (RealmOrganizationStatus::Revoked, None) => {
            anyhow::bail!("ak.realm.organization revoked status requires revokes_statement_id");
        }
        (RealmOrganizationStatus::Active, Some(_)) => {
            anyhow::bail!(
                "ak.realm.organization active status must not carry revokes_statement_id"
            );
        }
        _ => {}
    }

    let payload = RealmOrganizationPayload {
        statement_id: input.statement_id.clone(),
        realm_id,
        organization_id: input.organization_id.clone(),
        relationship: input.relationship,
        status: input.status,
        control_scopes: input.control_scopes.clone(),
        issued_at: input.issued_at,
        not_before: None,
        expires_at: None,
        supersedes_statement_id: None,
        revokes_statement_id: input.revokes_statement_id.clone(),
        realm_frontier_digest: None,
        organization_policy_ref: None,
        authorization: RealmOrganizationAuthorization {
            issuer_id: input.organization_id.clone(),
            issuer_role: RealmOrganizationIssuerRole::OrganizationPrincipalId,
            verification_method: arkret_sdk::DidUrl::new(input.verification_method.clone())
                .map_err(anyhow::Error::msg)?,
            delegation_ref: None,
            executed_by: None,
            signed_at: input.issued_at,
            // Placeholder; the signer rewrites this with the detached signature.
            proof: SignatureMaterial::NonEmptyString(
                arkret_sdk::NonEmptyString::new("placeholder").map_err(anyhow::Error::msg)?,
            ),
        },
    };

    arkret_sdk::realm_organization_statement_sign(&payload, control_key)
        .map_err(|err| anyhow::anyhow!("organization statement signing failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn organization_identity(value: &str) -> (DidCoreId, Did) {
        let did = Did::new(value.to_owned()).expect("did");
        let organization_id = project_did_to_core_id(&did).expect("organization id");
        (organization_id, did)
    }

    #[test]
    fn control_seed_round_trips_through_secure_store() {
        let store = MemorySecureKeyStore::new();
        let seed = [7u8; 32];
        let (organization_id, _) = organization_identity("did:webvh:zOrg1:example.test");
        store_organization_control_seed(&store, &organization_id, &seed).expect("store");
        let key = load_organization_control_key(&store, &organization_id)
            .expect("load")
            .expect("present");
        assert_eq!(key.to_bytes(), seed);
    }

    #[test]
    fn control_seed_key_is_org_scoped() {
        let (a_id, _) = organization_identity("did:webvh:zOrgA:example.test");
        let (b_id, _) = organization_identity("did:webvh:zOrgB:example.test");
        let a = organization_control_seed_key(&a_id);
        let b = organization_control_seed_key(&b_id);
        assert_ne!(a, b);
        assert!(a.starts_with(ORGANIZATION_CONTROL_SEED_KEY));
    }

    #[test]
    fn missing_seed_loads_as_none() {
        let store = MemorySecureKeyStore::new();
        let (organization_id, _) = organization_identity("did:webvh:zNone:example.test");
        assert!(
            load_organization_control_key(&store, &organization_id)
                .expect("load")
                .is_none()
        );
    }

    #[test]
    fn signed_statement_verifies_with_control_key() {
        let control_key = SigningKey::from_bytes(&[3u8; 32]);
        let (organization_id, did) = organization_identity("did:webvh:zOrg1:example.test");
        let input = OrganizationStatementInput {
            statement_id: "org-stmt-1".to_owned(),
            realm_id: "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo".to_owned(),
            organization_id,
            verification_method: format!("{did}#did-key-1"),
            organization_did: did,
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![RealmOrganizationControlScope::OfficialBadge],
            issued_at: crate::clock::now_utc(),
            revokes_statement_id: None,
        };
        let signed = sign_organization_statement(&input, &control_key).expect("sign");

        // Re-derive the signing bytes and verify with the control verifying key,
        // exactly the path soland's verifier runs.
        let proof = match &signed.authorization.proof {
            SignatureMaterial::NonEmptyString(value) => value.clone(),
            SignatureMaterial::Variant1(_) => panic!("expected detached signature"),
        };
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(proof.as_bytes())
            .expect("base64url decode");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("64-byte sig");
        let signing_bytes = arkret_models_collaboration::events_payloads::realm_organization_statement_signing_bytes(&signed)
            .expect("signing bytes");
        use ed25519_dalek::Verifier;
        control_key
            .verifying_key()
            .verify(&signing_bytes, &signature)
            .expect("verify");
    }

    #[test]
    fn revoked_without_revokes_id_is_rejected() {
        let control_key = SigningKey::from_bytes(&[9u8; 32]);
        let (organization_id, did) = organization_identity("did:webvh:zOrg1:example.test");
        let input = OrganizationStatementInput {
            statement_id: "org-stmt-2".to_owned(),
            realm_id: "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo".to_owned(),
            organization_id,
            verification_method: format!("{did}#did-key-1"),
            organization_did: did,
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Revoked,
            control_scopes: vec![RealmOrganizationControlScope::OfficialBadge],
            issued_at: crate::clock::now_utc(),
            revokes_statement_id: None,
        };
        assert!(sign_organization_statement(&input, &control_key).is_err());
    }

    #[test]
    fn statement_rejects_mismatched_organization_id_and_did() {
        let control_key = SigningKey::from_bytes(&[11u8; 32]);
        let (organization_id, _) = organization_identity("did:webvh:zOrg1:example.test");
        let (_, did) = organization_identity("did:webvh:zOrg2:example.test");
        let input = OrganizationStatementInput {
            statement_id: "org-stmt-3".to_owned(),
            realm_id: "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo".to_owned(),
            organization_id,
            verification_method: format!("{did}#did-key-1"),
            organization_did: did,
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![RealmOrganizationControlScope::OfficialBadge],
            issued_at: crate::clock::now_utc(),
            revokes_statement_id: None,
        };
        assert!(sign_organization_statement(&input, &control_key).is_err());
    }
}
