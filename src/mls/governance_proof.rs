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
    state_store: &crate::state::LocalStateStore,
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
        trusted_anchor_seal_id: state_store
            .trusted_mls_governance_anchor(realm_id.as_str())
            .or_else(|| {
                state_store
                    .seal_view_for_realm(realm_id.as_str())
                    .frontier
                    .first()
                    .and_then(|anchor| arkret_sdk::SealId::new(anchor.clone()).ok())
            })
            .ok_or_else(|| {
                format!(
                    "MLS governance proof requires a locally trusted Seal anchor for {realm_id}"
                )
            })?,
        chunk_index: 0,
        expected_bundle_digest: None,
    };
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    Ok(request)
}

pub(crate) async fn fetch_proof_bundle(
    api: &crate::transport::TransportClient,
    request: &arkret_sdk::MlsGovernanceProofRequest,
) -> Result<arkret_sdk::MaterializedMlsGovernanceProofBundle, String> {
    const MAX_PROJECTION_ATTEMPTS: u32 = 8;

    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance proof client: {error}"))?;
    for attempt in 0..MAX_PROJECTION_ATTEMPTS {
        match http.mls_governance_proof_complete(request).await {
            Ok(bundle) => return Ok(bundle),
            Err(error)
                if attempt + 1 < MAX_PROJECTION_ATTEMPTS
                    && governance_projection_pending(&error) =>
            {
                let delay_ms = (100_u64 << attempt).min(1_000);
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(error) => return Err(format!("fetch MLS governance proof: {error}")),
        }
    }
    unreachable!("bounded governance proof retry loop always returns")
}

fn governance_projection_pending(error: &arkret_sdk::Error) -> bool {
    matches!(
        error,
        arkret_sdk::Error::Api { status: 409, error }
            if error.code() == "state_mismatch"
                && error.message().to_ascii_lowercase().contains("bottom")
    )
}

pub(crate) fn welcome_proof_requests(
    state_store: &crate::state::LocalStateStore,
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
            state_store,
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
    let bundle = fetch_proof_bundle(api, request).await?;
    let existing_pin = state_store
        .read()
        .trusted_mls_governance_anchor(request.realm_id.as_str());
    if existing_pin.is_none() && !bundle_intersects_local_seal_view(&state_store.read(), &bundle) {
        let observed = api
            .event_submitter()
            .map_err(|error| format!("MLS governance proof frontier client: {error}"))?
            .events_frontier_realm_seal_view(request.realm_id.as_str())
            .await
            .map_err(|error| {
                format!("refresh accepted Seal view before governance trust bootstrap: {error}")
            })?;
        let observed_view = crate::state::LocalSealView {
            frontier: vec![observed.seal_id.to_string()],
            state_root: Some(observed.state_root.to_string()),
            ..Default::default()
        };
        if !bundle_intersects_seal_view(&observed_view, &bundle) {
            return Err(format!(
                "MLS governance proof cannot bootstrap trust: its Seal path does not intersect the freshly observed Seal head {} or state_root {}",
                observed.seal_id, observed.state_root
            ));
        }
        state_store
            .write()
            .set_realm_seal_view(request.realm_id.as_str(), observed_view);
    }
    let trusted_anchor = request.trusted_anchor_seal_id.clone();

    let authority = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        crate::identity::did_resolver::DidResolutionCache::default(),
    );
    let mut resolver = StaticProofDidResolver::default();
    for did in authority_proof_signer_dids(&bundle)? {
        let document = resolve_proof_signer_document(api, &did).await?;
        resolver.documents.insert(did.as_str().to_owned(), document);
    }
    for (actor, device) in event_device_proof_pairs(&bundle)? {
        let key = crate::identity::device_directory::resolve_device_signing_key(
            api, &authority, &actor, &device,
        )
        .await
        .map_err(|error| {
            format!(
                "resolve MLS governance frontier Event device key for {actor}#{device}: {error}"
            )
        })?;
        if key.is_none() {
            return Err(format!(
                "authoritative device key unavailable for MLS governance frontier Event signer {actor}#{device}"
            ));
        }
    }
    verify_proof_bundle(request, &bundle, &trusted_anchor, &resolver)?;
    let mut store = state_store.write();
    if existing_pin.is_none() {
        store
            .pin_mls_governance_anchor(request.realm_id.as_str(), &bundle.trusted_anchor_seal_id)?;
    }
    store.cache_verified_mls_governance_proof(request.clone(), &bundle)?;
    Ok(bundle.governance_binding)
}

async fn resolve_proof_signer_document(
    api: &crate::transport::TransportClient,
    did: &arkret_sdk::Did,
) -> Result<arkret_sdk::DidDocument, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance proof DID client: {error}"))?;
    let outcome = crate::transport::account::identity_resolve(&http, did.as_str())
        .await
        .map_err(|error| {
            format!(
                "authority DID resolution failed for MLS governance proof signer {did}: {error}"
            )
        })?;
    if outcome
        .did_document
        .get("id")
        .and_then(serde_json::Value::as_str)
        != Some(did.as_str())
    {
        return Err(format!(
            "authority DID resolution returned a different DID for MLS governance proof signer {did}"
        ));
    }
    let document: arkret_sdk::DidDocument = serde_json::to_value(outcome.did_document)
        .and_then(serde_json::from_value)
        .map_err(|error| {
            format!("decode authority DID document for MLS governance proof signer {did}: {error}")
        })?;
    if document.id != *did {
        return Err(format!(
            "authority DID document id {} does not match MLS governance proof signer {did}",
            document.id
        ));
    }
    Ok(document)
}

fn bundle_intersects_local_seal_view(
    state_store: &crate::state::LocalStateStore,
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
) -> bool {
    let view = state_store.seal_view_for_realm(bundle.realm_id.as_str());
    bundle_intersects_seal_view(&view, bundle)
}

fn bundle_intersects_seal_view(
    view: &crate::state::LocalSealView,
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
) -> bool {
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

pub(crate) fn authority_proof_signer_dids(
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
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
            if event_device_proof_pair(event, proof)?.is_none() {
                signers.insert(
                    verification_method_did(&proof.verification_method)
                        .map_err(|error| format!("invalid Event verification method: {error}"))?,
                );
            }
        }
    }
    Ok(signers)
}

fn event_device_proof_pairs(
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut pairs = BTreeSet::new();
    for event in &bundle.frontier_events {
        for proof in &event.proofs {
            if let Some(pair) = event_device_proof_pair(event, proof)? {
                pairs.insert(pair);
            }
        }
    }
    Ok(pairs)
}

fn event_device_proof_pair(
    event: &arkret_sdk::Event,
    proof: &arkret_sdk::Proof,
) -> Result<Option<(String, String)>, String> {
    if event.executed_by.is_some() {
        return Ok(None);
    }
    let signer = verification_method_did(&proof.verification_method)
        .map_err(|error| format!("invalid Event verification method: {error}"))?;
    if signer != event.actor_id {
        return Err(format!(
            "MLS governance frontier Event signer {signer} does not match actor {}",
            event.actor_id
        ));
    }
    let Some(fragment) = proof
        .verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .map(|fragment| fragment.split_once('?').map_or(fragment, |(head, _)| head))
        .filter(|fragment| !fragment.is_empty())
    else {
        return Ok(None);
    };
    if arkret_sdk::DeviceId::new(fragment.to_owned()).is_err() {
        return Ok(None);
    }
    Ok(Some((signer.as_str().to_owned(), fragment.to_owned())))
}

pub(crate) fn verify_proof_bundle<R>(
    request: &arkret_sdk::MlsGovernanceProofRequest,
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
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
                if let Some((actor, device)) = event_device_proof_pair(event, proof)
                    .map_err(arkret_sdk::Error::Protocol)?
                {
                    let key = match crate::identity::device_directory::cached_device_signing_key(
                        &actor, &device,
                    ) {
                        crate::identity::device_directory::CacheLookup::Hit(key) => key,
                        crate::identity::device_directory::CacheLookup::NegativeHit => {
                            return Err(arkret_sdk::Error::Protocol(format!(
                                "MLS governance frontier Event device key is revoked or unavailable for {actor}#{device}"
                            )));
                        }
                        crate::identity::device_directory::CacheLookup::Miss => {
                            return Err(arkret_sdk::Error::Protocol(format!(
                                "MLS governance frontier Event device key was not prefetched for {actor}#{device}"
                            )));
                        }
                    };
                    let envelope = event.digest_payload().map_err(|error| {
                        arkret_sdk::Error::Protocol(format!(
                            "materialize signed MLS governance frontier Event transcript: {error}"
                        ))
                    })?;
                    let proof_value = serde_json::to_value(proof).map_err(|error| {
                        arkret_sdk::Error::Protocol(format!(
                            "serialize MLS governance frontier Event proof: {error}"
                        ))
                    })?;
                    if !crate::identity::device_directory::verify_proof_value(
                        &envelope,
                        &proof_value,
                        &actor,
                        &key,
                    ) {
                        return Err(arkret_sdk::Error::Protocol(
                            "MLS governance frontier Event device proof is invalid".to_owned(),
                        ));
                    }
                } else {
                    let verified =
                        arkret_sdk::verify_event_proof_with_did_resolver(event, proof, resolver)?;
                    if !verified.valid {
                        return Err(arkret_sdk::Error::Protocol(
                            "MLS governance frontier Event proof is invalid".to_owned(),
                        ));
                    }
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
    if pinned != bundle.trusted_anchor_seal_id {
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
        state_store,
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
    let bundle = arkret_sdk::MaterializedMlsGovernanceProofBundle {
        bundle_version: arkret_sdk::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        proof_request_digest: request.proof_request_digest().unwrap(),
        bundle_digest: root.clone(),
        materialization_profile: arkret_sdk::MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE
            .to_owned(),
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        reducer_profile: request.reducer_profile.clone(),
        governance_binding: binding.clone(),
        trusted_anchor_seal_id: anchor.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frontier_event(actor: &str) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            "ak.member.state",
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
            arkret_sdk::Did::new(actor.to_owned()).unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e".to_owned()).unwrap(),
            serde_json::json!({}),
        )
        .unwrap()
    }

    fn proof(verification_method: &str) -> arkret_sdk::Proof {
        arkret_sdk::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            event_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            )
            .unwrap(),
            created_at: chrono::Utc::now(),
            domain: None,
            audience: None,
            jws: "test".to_owned(),
        }
    }

    #[test]
    fn frontier_device_proof_uses_device_directory_pair() {
        let actor = "did:webvh:zfixture:alice.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let event = frontier_event(actor);

        assert_eq!(
            event_device_proof_pair(&event, &proof(&format!("{actor}#{device}"))).unwrap(),
            Some((actor.to_owned(), device.to_owned()))
        );
    }

    #[test]
    fn frontier_root_key_proof_stays_on_did_authority_path() {
        let actor = "did:webvh:zfixture:alice.example";
        let event = frontier_event(actor);

        assert_eq!(
            event_device_proof_pair(&event, &proof(&format!("{actor}#root-key"))).unwrap(),
            None
        );
    }

    #[test]
    fn frontier_device_proof_rejects_controller_mismatch() {
        let event = frontier_event("did:webvh:zfixture:alice.example");
        let error = event_device_proof_pair(
            &event,
            &proof(
                "did:webvh:zfixture:mallory.example#ak:device:01904100-0000-7000-8000-0000000000a1",
            ),
        )
        .expect_err("controller mismatch must fail");

        assert!(error.contains("does not match actor"), "{error}");
    }

    #[test]
    fn only_bottom_projection_conflicts_are_retryable() {
        let pending = arkret_sdk::Error::Api {
            status: 409,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(
                "state_mismatch",
                "member cell is still Bottom",
            )),
        };
        let policy_denial = arkret_sdk::Error::Api {
            status: 409,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(
                "state_mismatch",
                "governance policy digest differs",
            )),
        };

        assert!(governance_projection_pending(&pending));
        assert!(!governance_projection_pending(&policy_denial));
        assert!(!governance_projection_pending(
            &arkret_sdk::Error::Protocol("member cell is still Bottom".to_owned(),)
        ));
    }
}

fn target_notary_value(
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
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
    let genesis_events = bundle
        .frontier_events
        .iter()
        .filter(|event| event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE)
        .collect::<Vec<_>>();
    if genesis_events.len() > 1 {
        return Err("MLS governance proof contains multiple Realm genesis Events".to_owned());
    }
    if let Some(genesis) = genesis_events.first() {
        let genesis_notary = genesis
            .payload
            .get("object")
            .and_then(|object| object.get("notary"))
            .cloned()
            .ok_or_else(|| {
                "MLS governance Realm genesis Event omits payload.object.notary".to_owned()
            })?;
        let genesis_notary = serde_json::from_value::<arkret_sdk::NotaryValue>(genesis_notary)
            .map_err(|error| format!("decode MLS governance genesis notary: {error}"))?;
        genesis_notary
            .validate()
            .map_err(|error| format!("invalid MLS governance genesis notary: {error}"))?;
        if genesis_notary != notary {
            return Err(
                "MLS governance proof notary cell differs from the signed Realm genesis Event"
                    .to_owned(),
            );
        }
    } else if matches!(
        bundle.effective_scope,
        arkret_sdk::models::EffectiveScope::Realm { .. }
    ) {
        return Err("Realm-scoped MLS governance proof omits its genesis Event".to_owned());
    }
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
