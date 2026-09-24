//! Historical Station keys for a Realm authority bundle and scan page.
//!
//! A current DID document cannot authenticate an old Commit. Each signature
//! is resolved against complete method-native history at its accepted Commit
//! or bundle coordinate; mutable did:web has no historical key source and fails closed.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, ensure};
use arkret_identity::{
    DidVerificationRelationship, RealmAuthorityKeyMap, authenticated_service_document_at,
    resolve_verification_method_key_from_document, validate_verification_method_relationship,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_sdk::{DetachedObjectSignature, DidCoreId, RealmAuthorityBundle, StreamScanOutcome};
use arkret_signatures::PublicKeyMaterial;
use chrono::{DateTime, Utc};

struct SignedStationMethod<'a> {
    signature: &'a DetachedObjectSignature,
    accepted_at: DateTime<Utc>,
}

fn signed_methods<'a>(
    bundle: &'a RealmAuthorityBundle,
    scan: Option<&'a StreamScanOutcome>,
) -> Vec<SignedStationMethod<'a>> {
    let mut methods = vec![SignedStationMethod {
        signature: &bundle.genesis_commit.signature,
        accepted_at: bundle.genesis_commit.committed_at,
    }];
    for transition in &bundle.authority_transitions {
        methods.push(SignedStationMethod {
            signature: &transition.change_commit.signature,
            accepted_at: transition.change_commit.committed_at,
        });
        for signature in [
            &transition.handoff.old_authority_signature,
            &transition.handoff.new_authority_acceptance_signature,
        ] {
            methods.push(SignedStationMethod {
                signature,
                accepted_at: signature
                    .created_at
                    .max(transition.change_commit.committed_at),
            });
        }
    }
    methods.push(SignedStationMethod {
        signature: &bundle.current_assertion.signature,
        accepted_at: bundle.bundle_issued_at,
    });
    if let Some(scan) = scan {
        methods.extend(scan.committed_events.iter().map(|item| {
            let commit = item.commit();
            SignedStationMethod {
                signature: &commit.signature,
                accepted_at: commit.committed_at,
            }
        }));
    }
    methods
}

fn station_id_for_signature(signature: &DetachedObjectSignature) -> Result<DidCoreId> {
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str())?;
    Ok(arkret_sdk::project_did_to_core_id(&did)?)
}

fn historical_key_for_signature(
    resolution: &AuthenticatedServiceResolution,
    signature: &DetachedObjectSignature,
    accepted_at: DateTime<Utc>,
) -> Result<PublicKeyMaterial> {
    let service_id = station_id_for_signature(signature)?;
    ensure!(
        resolution.service_id == service_id && resolution.service_kind == "station",
        "historical Station resolution identity or kind mismatch"
    );
    let document = authenticated_service_document_at(resolution, &service_id, accepted_at)?;
    let method = &signature.verification_method;
    let controller = arkret_identity::verification_method_did(method.as_str())?;
    validate_verification_method_relationship(
        &document,
        method,
        &controller,
        DidVerificationRelationship::AssertionMethod,
    )?;
    Ok(resolve_verification_method_key_from_document(&document, method.as_str())?.public_key)
}

/// List every Station whose signed historical material the verifier needs.
/// The caller fetches complete authenticated service resolutions for these
/// exact ids; absent material remains an error, never a current-key fallback.
pub(crate) fn required_station_ids(
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanOutcome>,
) -> Result<Vec<DidCoreId>> {
    let mut ids = signed_methods(bundle, scan)
        .iter()
        .map(|entry| station_id_for_signature(entry.signature))
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Build the exact-method directory consumed by Garth's cryptographic gate.
/// Resolutions must already be fetched as complete method-native carriers;
/// this function verifies each at the signature's historical coordinate.
pub(crate) fn verified_key_directory(
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanOutcome>,
    resolutions: &BTreeMap<DidCoreId, AuthenticatedServiceResolution>,
) -> Result<RealmAuthorityKeyMap> {
    let mut keys = RealmAuthorityKeyMap::new();
    for entry in signed_methods(bundle, scan) {
        let service_id = station_id_for_signature(entry.signature)?;
        let resolution = resolutions
            .get(&service_id)
            .with_context(|| format!("missing historical Station resolution {service_id}"))?;
        let method = &entry.signature.verification_method;
        let material =
            historical_key_for_signature(resolution, entry.signature, entry.accepted_at)?;
        if let Some(previous) = keys.insert(method, material.clone()) {
            ensure!(
                previous == material,
                "historical Station method changed key material"
            );
        }
    }
    ensure!(
        !keys.is_empty(),
        "authority bundle has no Station signing key"
    );
    Ok(keys)
}

/// Fetch missing Station resolution carriers through the typed public SDK
/// endpoint. The current route record only supplies the current Station;
/// prior generations require their own complete histories.
pub(crate) async fn fetch_verified_key_directory(
    http: &arkret_sdk::http_client::Client,
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanOutcome>,
) -> Result<RealmAuthorityKeyMap> {
    let current: AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record.clone())
            .context("current authority route is not a typed service resolution")?;
    ensure!(
        current.service_id == bundle.current_service_id,
        "current authority route belongs to another Station"
    );
    let mut resolutions = BTreeMap::from([(current.service_id.clone(), current)]);
    for service_id in required_station_ids(bundle, scan)? {
        if resolutions.contains_key(&service_id) {
            continue;
        }
        let resolution = http
            .open_service_resolution(&service_id)
            .await
            .map_err(|error| anyhow!("historical Station resolution {service_id}: {error}"))?;
        resolutions.insert(service_id, resolution);
    }
    verified_key_directory(bundle, scan, &resolutions)
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{
        Base64UrlString, DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidUrl, Hash,
    };
    use arkret_signatures::webvh::{
        ServiceInceptionInput, prepare_service_inception_with_did_key_seed,
    };
    use chrono::{Duration, TimeZone as _};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng as _;
    use url::Url;

    use super::*;

    #[test]
    fn complete_webvh_history_selects_the_station_key_at_acceptance() {
        let inception_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(73);
        let signing_seed = [41_u8; 32];
        let prepared = prepare_service_inception_with_did_key_seed(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &Url::parse("https://station.example/").unwrap(),
                local_id: "service",
                also_known_as: &[],
                version_time: inception_at,
                did_key_fragment: Some("realm-authority"),
            },
            &signing_seed,
        )
        .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let service_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let document = serde_json::from_value(prepared.log_entry["state"].clone()).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id,
            "station".to_owned(),
            document,
            vec![prepared.log_entry.clone()],
            vec![],
            inception_at + Duration::seconds(30),
        )
        .unwrap();
        let signature = DetachedObjectSignature {
            context: DetachedSignatureContext::RealmCommit,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new(prepared.did_key_id.clone()).unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: inception_at + Duration::seconds(10),
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let key =
            historical_key_for_signature(&resolution, &signature, signature.created_at).unwrap();
        assert_eq!(
            key,
            PublicKeyMaterial::Ed25519Multibase {
                value: prepared.did_public_key_multibase.clone(),
            }
        );
        assert!(
            historical_key_for_signature(
                &resolution,
                &signature,
                inception_at - Duration::seconds(1)
            )
            .is_err()
        );
        let mut wrong_method = signature;
        wrong_method.verification_method =
            DidUrl::new(format!("{}#unknown", did.as_str())).unwrap();
        assert!(
            historical_key_for_signature(
                &resolution,
                &wrong_method,
                inception_at + Duration::seconds(10)
            )
            .is_err()
        );
    }

    #[test]
    fn mutable_did_web_document_cannot_supply_a_historical_station_key() {
        let at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let did = Did::new("did:web:station.example").unwrap();
        let method = DidUrl::new("did:web:station.example#authority").unwrap();
        let document = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": method,
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&[47; 32]).verifying_key().as_bytes()
                )
            }],
            "assertionMethod": [method],
            "service": [{
                "id": "did:web:station.example#station",
                "type": "ArkretService",
                "serviceEndpoint": "https://station.example/",
                "serviceKind": "station"
            }]
        }))
        .unwrap();
        let service_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let resolution = arkret_identity::build_authenticated_did_web_service_resolution(
            service_id,
            "station".to_owned(),
            document,
            at,
        )
        .unwrap();
        let signature = DetachedObjectSignature {
            context: DetachedSignatureContext::RealmCommit,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: method,
            signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            sig: Base64UrlString::new("AA").unwrap(),
        };
        assert!(historical_key_for_signature(&resolution, &signature, at).is_err());
    }
}
