use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::identity::{DidResolver, verification_method_did};
use arkret_sdk::{NotarySig, Seal};
use dioxus::prelude::{ReadableExt, WritableExt};

#[derive(Default)]
struct StaticProofDidResolver {
    documents: BTreeMap<String, arkret_sdk::DidDocument>,
}

impl DidResolver for StaticProofDidResolver {
    fn supports(&self, did: &arkret_sdk::Did) -> bool {
        self.documents.contains_key(did.as_str())
    }

    fn resolve_did(&self, did: &arkret_sdk::Did) -> arkret_sdk::Result<arkret_sdk::DidDocument> {
        self.documents.get(did.as_str()).cloned().ok_or_else(|| {
            arkret_sdk::Error::Protocol(format!(
                "no authority-resolved DID document for proof signer {did}"
            ))
        })
    }
}

pub(crate) fn proof_request(
    realm_id: &str,
    circle_id: Option<&str>,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
) -> Result<arkret_sdk::MlsGovernanceProofRequest, String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS governance proof Realm id: {error}"))?;
    let effective_scope = match circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty())
    {
        Some(circle_id) => arkret_sdk::models::EffectiveScope::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| format!("invalid MLS governance proof Circle id: {error}"))?,
        },
        None => arkret_sdk::models::EffectiveScope::Realm {
            realm_id: realm_id.clone(),
        },
    };
    let request = arkret_sdk::MlsGovernanceProofRequest {
        realm_id,
        effective_scope,
        mls_group_id: mls_group_id.into(),
        previous_epoch,
        next_epoch,
        binding_profile: arkret_sdk::MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
        reducer_profile: "ak.reducer.v1".to_owned(),
    };
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    Ok(request)
}

pub(crate) async fn fetch_proof_bundle(
    api: &crate::transport::TransportClient,
    request: &arkret_sdk::MlsGovernanceProofRequest,
) -> Result<arkret_sdk::MlsGovernanceProofBundle, String> {
    api.sdk_http_client()
        .map_err(|error| format!("build MLS governance proof client: {error}"))?
        .mls_governance_proof(request)
        .await
        .map_err(|error| format!("fetch MLS governance proof: {error}"))
}

pub(crate) fn welcome_proof_requests(
    messages: &serde_json::Value,
) -> Result<Vec<arkret_sdk::MlsGovernanceProofRequest>, String> {
    let Some(entries) = messages
        .get("messages")
        .or_else(|| messages.get("events"))
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };
    let mut requests = Vec::new();
    for entry in entries {
        if entry
            .get("kind")
            .or_else(|| entry.get("type"))
            .and_then(serde_json::Value::as_str)
            != Some("ak.mls.welcome")
        {
            continue;
        }
        let binding_value = entry
            .get("content")
            .and_then(|content| content.get("governance_binding"))
            .ok_or_else(|| "durable MLS Welcome omits governance_binding".to_owned())?;
        let binding: arkret_sdk::MlsGovernanceBindingPayload =
            serde_json::from_value(binding_value.clone())
                .map_err(|error| format!("decode MLS Welcome governance_binding: {error}"))?;
        let request = proof_request(
            binding.realm_id().as_str(),
            binding.circle_id().map(|circle_id| circle_id.as_str()),
            binding.mls_group_id(),
            binding.previous_epoch(),
            binding.next_epoch(),
        )?;
        if !requests.contains(&request) {
            requests.push(request);
        }
    }
    Ok(requests)
}

pub(crate) async fn fetch_verify_and_cache_proof(
    api: &crate::transport::TransportClient,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    request: &arkret_sdk::MlsGovernanceProofRequest,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    use crate::identity::device_directory::DidAnchor as _;

    let bundle = fetch_proof_bundle(api, request).await?;
    let existing_pin = state_store
        .read()
        .trusted_mls_governance_anchor(request.realm_id.as_str());
    if existing_pin.is_none() && !bundle_intersects_local_seal_view(&state_store.read(), &bundle) {
        return Err(
            "MLS governance proof cannot bootstrap trust: its Seal path does not intersect the locally observed Seal head or state_root"
                .to_owned(),
        );
    }
    let trusted_anchor = existing_pin
        .clone()
        .unwrap_or_else(|| bundle.trust_anchor_seal_id.clone());

    let authority = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        crate::identity::did_resolver::DidResolutionCache::default(),
    );
    let http = reqwest::Client::new();
    let mut resolver = StaticProofDidResolver::default();
    for did in proof_signer_dids(&bundle)? {
        if !authority.ensure_actor_document(&http, &did).await {
            return Err(format!(
                "authority DID resolution failed for MLS governance proof signer {did}"
            ));
        }
        let document = authority.resolve_did_document(&did).ok_or_else(|| {
            format!("authority DID document unavailable for MLS governance proof signer {did}")
        })?;
        resolver.documents.insert(did.as_str().to_owned(), document);
    }
    verify_proof_bundle(request, &bundle, &trusted_anchor, &resolver)?;
    let mut store = state_store.write();
    if existing_pin.is_none() {
        store.pin_mls_governance_anchor(request.realm_id.as_str(), &bundle.trust_anchor_seal_id)?;
    }
    store.cache_verified_mls_governance_proof(request.clone(), &bundle)?;
    Ok(bundle.governance_binding)
}

fn bundle_intersects_local_seal_view(
    state_store: &crate::state::LocalStateStore,
    bundle: &arkret_sdk::MlsGovernanceProofBundle,
) -> bool {
    let view = state_store.seal_view_for_realm(bundle.realm_id.as_str());
    let local_heads = view
        .frontier
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if bundle
        .seal_path
        .iter()
        .any(|seal| local_heads.contains(seal.id.as_str()))
    {
        return true;
    }
    let local_state_root = view
        .state_root
        .as_deref()
        .and_then(crate::mls::group_events::mls_sha256_hash_from_ref);
    local_state_root.is_some_and(|root| {
        bundle
            .seal_path
            .iter()
            .any(|seal| seal.state_root.as_str() == root)
    })
}

pub(crate) fn proof_signer_dids(
    bundle: &arkret_sdk::MlsGovernanceProofBundle,
) -> Result<BTreeSet<arkret_sdk::Did>, String> {
    let mut signers = BTreeSet::new();
    for seal in &bundle.seal_path {
        match &seal.notary_signature {
            NotarySig::Single(signature) => {
                signers.insert(
                    verification_method_did(&signature.verification_method)
                        .map_err(|error| format!("invalid Seal verification method: {error}"))?,
                );
            }
            NotarySig::Multi(multi) => {
                for signature in &multi.signatures {
                    signers.insert(
                        verification_method_did(&signature.verification_method).map_err(
                            |error| format!("invalid Seal verification method: {error}"),
                        )?,
                    );
                }
            }
            NotarySig::Threshold(_) => {
                return Err(
                    "threshold Seal proofs are unsupported by the current client verifier"
                        .to_owned(),
                );
            }
        }
    }
    for event in &bundle.frontier_events {
        for proof in &event.proofs {
            signers.insert(
                verification_method_did(&proof.verification_method)
                    .map_err(|error| format!("invalid Event verification method: {error}"))?,
            );
        }
    }
    Ok(signers)
}

pub(crate) fn verify_proof_bundle<R>(
    request: &arkret_sdk::MlsGovernanceProofRequest,
    bundle: &arkret_sdk::MlsGovernanceProofBundle,
    trusted_anchor: &arkret_sdk::SealId,
    resolver: &R,
) -> Result<arkret_sdk::VerifiedMlsGovernanceProof, String>
where
    R: DidResolver,
{
    verify_request_binding(request, &bundle.governance_binding)?;
    let notary = target_notary_value(bundle)?;
    arkret_sdk::verify_mls_governance_proof_bundle(
        bundle,
        &bundle.governance_binding,
        trusted_anchor,
        |seal| verify_seal(seal, &notary, resolver),
        |event| {
            if event.proofs.is_empty() {
                return Err(arkret_sdk::Error::Protocol(
                    "MLS governance frontier Event has no proof".to_owned(),
                ));
            }
            for proof in &event.proofs {
                let verified =
                    arkret_sdk::verify_event_proof_with_did_resolver(event, proof, resolver)?;
                if !verified.valid {
                    return Err(arkret_sdk::Error::Protocol(
                        "MLS governance frontier Event proof is invalid".to_owned(),
                    ));
                }
            }
            Ok(())
        },
    )
    .map_err(|error| format!("verify MLS governance proof: {error}"))
}

pub(crate) fn cached_verified_binding(
    state_store: &crate::state::LocalStateStore,
    request: &arkret_sdk::MlsGovernanceProofRequest,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    let bundle = state_store
        .cached_mls_governance_proof(request, chrono::Utc::now())?
        .ok_or_else(|| {
            "full-profile MLS governance binding requires a fresh, locally verified accepted-Seal proof bundle; operation remains decryption_pending (state_mismatch)"
                .to_owned()
        })?;
    verify_request_binding(request, &bundle.governance_binding)?;
    let pinned = state_store
        .trusted_mls_governance_anchor(request.realm_id.as_str())
        .ok_or_else(|| "MLS governance trust anchor is not pinned".to_owned())?;
    if pinned != bundle.trust_anchor_seal_id {
        return Err("cached MLS governance proof no longer matches the pinned anchor".to_owned());
    }
    Ok(bundle.governance_binding)
}

#[cfg(test)]
pub(crate) fn seed_test_governance_proof(
    state_store: &mut crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
) -> arkret_sdk::MlsGovernanceBindingPayload {
    let request = proof_request(
        realm_id,
        circle_id,
        mls_group_id,
        previous_epoch,
        next_epoch,
    )
    .unwrap();
    let frontier =
        vec![arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-0000000000aa").unwrap()];
    let root = arkret_sdk::Hash::new(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let binding = match &request.effective_scope {
        arkret_sdk::models::EffectiveScope::Realm { realm_id } => {
            arkret_sdk::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                request.mls_group_id.clone(),
                previous_epoch,
                next_epoch,
                frontier,
                root.clone(),
                root.clone(),
                root,
                request.binding_profile.clone(),
                request.reducer_profile.clone(),
            )
        }
        arkret_sdk::models::EffectiveScope::Circle {
            realm_id,
            circle_id,
        } => arkret_sdk::MlsGovernanceBindingPayload::circle(
            realm_id.clone(),
            circle_id.clone(),
            request.mls_group_id.clone(),
            previous_epoch,
            next_epoch,
            frontier,
            root.clone(),
            root.clone(),
            root,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        _ => panic!("unsupported effective scope in MLS governance test fixture"),
    }
    .unwrap();
    let anchor = arkret_sdk::SealId::new(
        "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let bundle = arkret_sdk::MlsGovernanceProofBundle {
        bundle_version: arkret_sdk::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        materialization_profile: arkret_sdk::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
            .to_owned(),
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        reducer_profile: request.reducer_profile.clone(),
        governance_binding: binding.clone(),
        trust_anchor_seal_id: anchor.clone(),
        accepted_seal_id: anchor.clone(),
        seal_path: Vec::new(),
        covered_event_digests: Vec::new(),
        control_state: Vec::new(),
        frontier_events: Vec::new(),
    };
    state_store
        .pin_mls_governance_anchor(realm_id, &anchor)
        .unwrap();
    state_store
        .cache_verified_mls_governance_proof(request, &bundle)
        .unwrap();
    binding
}

fn verify_request_binding(
    request: &arkret_sdk::MlsGovernanceProofRequest,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<(), String> {
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    if binding.realm_id() != &request.realm_id
        || binding.effective_scope() != &request.effective_scope
        || binding.mls_group_id() != request.mls_group_id
        || binding.previous_epoch() != request.previous_epoch
        || binding.next_epoch() != request.next_epoch
        || binding.binding_profile() != request.binding_profile
        || binding.reducer_profile() != request.reducer_profile
    {
        return Err("MLS governance proof binding differs from the exact request".to_owned());
    }
    Ok(())
}

fn target_notary_value(
    bundle: &arkret_sdk::MlsGovernanceProofBundle,
) -> Result<arkret_sdk::NotaryValue, String> {
    let expected = format!(
        "ak:cell:ak.component.notary.v1:{}",
        bundle.realm_id.as_str()
    );
    let leaf = bundle
        .control_state
        .iter()
        .find(|leaf| leaf.cell.as_str() == expected)
        .ok_or_else(|| "MLS governance proof omits the Realm notary cell".to_owned())?;
    let notary: arkret_sdk::NotaryValue = serde_json::from_value(leaf.state.value.clone())
        .map_err(|error| format!("decode MLS governance proof notary cell: {error}"))?;
    notary
        .validate()
        .map_err(|error| format!("invalid MLS governance proof notary value: {error}"))?;
    Ok(notary)
}

fn verify_seal<R>(
    seal: &Seal,
    notary: &arkret_sdk::NotaryValue,
    resolver: &R,
) -> arkret_sdk::Result<()>
where
    R: DidResolver,
{
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    let signature = match &seal.notary_signature {
        NotarySig::Single(signature) => signature,
        NotarySig::Multi(_) | NotarySig::Threshold(_) => {
            return Err(arkret_sdk::Error::Protocol(
                "only single-signature Seal proofs are supported by this verifier".to_owned(),
            ));
        }
    };
    if signature.alg != "EdDSA" {
        return Err(arkret_sdk::Error::Protocol(
            "MLS governance Seal signature must use EdDSA".to_owned(),
        ));
    }
    let signer = verification_method_did(&signature.verification_method)?;
    if !notary.includes_signer_as_primary(&signer) {
        return Err(arkret_sdk::Error::Protocol(format!(
            "Seal signer {signer} is not authorized by the materialized Realm notary cell"
        )));
    }
    arkret_sdk::jws::verify_jws_ed25519(
        &canonical_bytes,
        &signature.jws,
        &signature.verification_method,
        signer.as_str(),
        resolver,
    )
    .map_err(|error| arkret_sdk::Error::Protocol(format!("Seal signature invalid: {error}")))
}
