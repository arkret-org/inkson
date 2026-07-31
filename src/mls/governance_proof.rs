use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::identity::{DidResolver, verification_method_did};
use arkret_sdk::{NotarySig, Seal};
use dioxus::prelude::{ReadableExt, WritableExt};

pub(crate) trait GovernanceProofStateStore: Clone {
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R;
    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R;
}

impl GovernanceProofStateStore for dioxus::prelude::SyncSignal<crate::state::LocalStateStore> {
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R {
        let store = ReadableExt::read(self);
        read(&store)
    }

    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R {
        let mut signal = *self;
        let mut store = WritableExt::write(&mut signal);
        write(&mut store)
    }
}

impl GovernanceProofStateStore for crate::runtime::input::StateStoreHandle {
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R {
        self.read(read)
    }

    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R {
        self.write(write)
    }
}

#[derive(Default)]
pub(crate) struct StaticProofDidResolver {
    pub(crate) documents: BTreeMap<String, arkret_sdk::DidDocument>,
}

impl DidResolver for StaticProofDidResolver {
    fn supports(&self, did: &arkret_sdk::Did) -> bool {
        self.documents.contains_key(did.as_str())
    }

    fn resolve_did(
        &self,
        did: &arkret_sdk::Did,
    ) -> arkret_sdk::identity::Result<arkret_sdk::DidDocument> {
        self.documents.get(did.as_str()).cloned().ok_or_else(|| {
            arkret_sdk::identity::IdentityError::Protocol(format!(
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
) -> Result<arkret_sdk::MlsGovernanceProofRequestBodyBody, String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS governance proof Realm id: {error}"))?;
    let effective_scope = match circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty())
    {
        Some(circle_id) => arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| format!("invalid MLS governance proof Circle id: {error}"))?,
        },
        None => arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
    };
    let request = arkret_sdk::MlsGovernanceProofRequestBodyBody {
        realm_id: realm_id.clone(),
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
                    "MLS governance proof requires a locally trusted Seal anchor for {realm_id}; operation remains decryption_pending (state_mismatch)"
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

async fn fetch_proof_bundle<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
) -> Result<arkret_sdk::MaterializedMlsGovernanceProofBundle, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance proof client: {error}"))?;
    let mut first_request = request.clone();
    first_request.chunk_index = 0;
    first_request.expected_bundle_digest = None;
    let first = fetch_proof_chunk_with_retry(&http, &first_request).await?;
    let mut chunks = state_store.with_read(|store| {
        store
            .cached_mls_governance_acquisition(&first_request)
            .unwrap_or_default()
    });
    let cached_matches = chunks.first().is_some_and(|cached| {
        cached.bundle_digest == first.bundle_digest
            && cached.proof_request_digest == first.proof_request_digest
            && cached.chunk_manifest == first.chunk_manifest
    });
    if !cached_matches {
        state_store.with_write(|store| store.clear_mls_governance_acquisition(&first_request))?;
        chunks.clear();
        chunks.push(first.clone());
        state_store.with_write(|store| {
            store.persist_mls_governance_acquisition_chunk(&first_request, &first)
        })?;
    }
    let chunk_count = first.chunk_manifest.chunk_count as usize;
    if chunks.len() > chunk_count {
        state_store.with_write(|store| store.clear_mls_governance_acquisition(&first_request))?;
        chunks = vec![first.clone()];
        state_store.with_write(|store| {
            store.persist_mls_governance_acquisition_chunk(&first_request, &first)
        })?;
    }
    for chunk_index in chunks.len()..chunk_count {
        let mut next_request = first_request.clone();
        next_request.chunk_index = chunk_index as u32;
        next_request.expected_bundle_digest = Some(first.bundle_digest.clone());
        let chunk = fetch_proof_chunk_with_retry(&http, &next_request).await?;
        if chunk.chunk.chunk_index() != chunk_index as u32
            || chunk.bundle_digest != first.bundle_digest
            || chunk.proof_request_digest != first.proof_request_digest
            || chunk.chunk_manifest != first.chunk_manifest
        {
            state_store
                .with_write(|store| store.clear_mls_governance_acquisition(&first_request))?;
            return Err(
                "MLS governance proof service changed manifest during acquisition".to_owned(),
            );
        }
        state_store.with_write(|store| {
            store.persist_mls_governance_acquisition_chunk(&first_request, &chunk)
        })?;
        chunks.push(chunk);
    }
    let materialized = arkret_sdk::assemble_mls_governance_proof_chunks(&first_request, &chunks)
        .map_err(|error| format!("assemble MLS governance proof chunks: {error}"))?;
    state_store.with_write(|store| store.clear_mls_governance_acquisition(&first_request))?;
    Ok(materialized)
}

async fn fetch_proof_chunk_with_retry(
    http: &arkret_sdk::Client,
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
) -> Result<arkret_sdk::MlsGovernanceProofBundle, String> {
    const MAX_PROJECTION_ATTEMPTS: u32 = 8;
    for attempt in 0..MAX_PROJECTION_ATTEMPTS {
        match http.mls_governance_proof(request).await {
            Ok(bundle) => return Ok(bundle),
            Err(error)
                if attempt + 1 < MAX_PROJECTION_ATTEMPTS
                    && governance_projection_pending(&error) =>
            {
                let delay_ms = (100_u64 << attempt).min(1_000);
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(error) => return Err(format!("fetch MLS governance proof chunk: {error}")),
        }
    }
    unreachable!("bounded governance proof retry loop always returns")
}

fn governance_projection_pending(error: &arkret_sdk::http_client::Error) -> bool {
    matches!(
        error,
        arkret_sdk::http_client::Error::Api { status: 409, error }
            if error.code() == "state_mismatch"
                && error.message().to_ascii_lowercase().contains("bottom")
    )
}

pub(crate) fn welcome_proof_requests(
    state_store: &crate::state::LocalStateStore,
    messages: &serde_json::Value,
) -> Result<Vec<arkret_sdk::MlsGovernanceProofRequestBodyBody>, String> {
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

pub(crate) async fn fetch_verify_and_cache_proof<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    Ok(
        fetch_verify_and_cache_proof_bundle(api, state_store, request)
            .await?
            .governance_binding,
    )
}

pub(crate) async fn fetch_verify_and_cache_proof_bundle<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
) -> Result<arkret_sdk::MaterializedMlsGovernanceProofBundle, String> {
    let bundle = fetch_proof_bundle(api, state_store.clone(), request).await?;
    let existing_pin = state_store
        .with_read(|store| store.trusted_mls_governance_anchor(request.realm_id.as_str()));
    if existing_pin.is_none()
        && !state_store.with_read(|store| bundle_intersects_local_seal_view(store, &bundle))
    {
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
        state_store.with_write(|store| {
            store.set_realm_seal_view(request.realm_id.as_str(), observed_view)
        });
    }
    let trusted_anchor = request.trusted_anchor_seal_id.clone();

    // DID-P2-B: reuse the account-level accepted-binding set instead of a
    // throw-away `DidResolutionCache::default()`.
    //
    // The previous code built an empty cache here and never called
    // `into_cache()`, so every DID this function resolved was discarded when
    // `authority` dropped — a governance-proof verification could not benefit
    // from, or contribute to, any other resolution in the app. The state store
    // is already threaded in as `S: GovernanceProofStateStore` (it owns the
    // trusted-anchor pin below), so the binding handle comes from there and no
    // call-site signature changes.
    let binding_scope = crate::identity::did_binding::DidBindingScope::for_server(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        api.base_url().as_str(),
    )
    .map_err(|error| format!("resolver policy digest: {error}"))?;
    let authority = crate::identity::did_resolver::ResolverDidAnchor::from_persisted_bindings(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        arkret_sdk::identity::DidResolutionCache::default(),
        binding_scope,
        arkret_sdk::identity::DidBindingPurpose::DeviceSigner,
        state_store.with_read(crate::state::LocalStateStore::accepted_did_bindings),
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
    let notary = target_notary_value(&bundle)?;
    let delegated_controller = managed_agent_pcr_delegated_controller(&bundle, &notary)?;
    for (actor, device) in managed_seal_device_proof_pairs(&bundle, delegated_controller.as_ref())?
    {
        let key = crate::identity::device_directory::resolve_device_signing_key(
            api, &authority, &actor, &device,
        )
        .await
        .map_err(|error| {
            format!(
                "resolve MLS governance Seal controller device key for {actor}#{device}: {error}"
            )
        })?;
        if key.is_none() {
            return Err(format!(
                "authoritative device key unavailable for MLS governance Seal controller {actor}#{device}"
            ));
        }
    }
    verify_proof_bundle(request, &bundle, &trusted_anchor, &resolver)?;
    // Persist whatever this verification accepted so the next boot (and every
    // other authority call site) reuses it instead of resolving again.
    if let (_, Some(records)) = authority.into_cache_and_bindings() {
        state_store.with_write(|store| store.store_accepted_did_bindings(records));
    }
    state_store.with_write(|store| {
        if existing_pin.is_none() {
            store.pin_mls_governance_anchor(
                request.realm_id.as_str(),
                &bundle.trusted_anchor_seal_id,
            )?;
        }
        store.cache_verified_mls_governance_proof(request.clone(), &bundle)
    })?;
    Ok(bundle)
}

pub(crate) async fn resolve_proof_signer_document(
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
    let signer = verification_method_did(&proof.verification_method)
        .map_err(|error| format!("invalid Event verification method: {error}"))?;
    let signing_actor = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    if &signer != signing_actor {
        return Err(format!(
            "MLS governance frontier Event signer {signer} does not match actor/executor {signing_actor}"
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

fn managed_seal_device_proof_pairs(
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
    delegated_controller: Option<&arkret_sdk::Did>,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut pairs = BTreeSet::new();
    for seal in &bundle.seal_path {
        if let Some(pair) = managed_seal_device_proof_pair(seal, delegated_controller)? {
            pairs.insert(pair);
        }
    }
    Ok(pairs)
}

fn managed_seal_device_proof_pair(
    seal: &Seal,
    delegated_controller: Option<&arkret_sdk::Did>,
) -> Result<Option<(String, String)>, String> {
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Ok(None);
    };
    delegated_device_verification_method_pair(&signature.verification_method, delegated_controller)
}

async fn ensure_managed_agent_pcr_seal_head_device_key_with<F, Fut>(
    seal: &Seal,
    controller: &arkret_sdk::Did,
    resolve: F,
) -> anyhow::Result<()>
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<
            Output = anyhow::Result<Option<arkret_sdk::signatures::PublicKeyMaterial>>,
        >,
{
    let (actor, device) = managed_seal_device_proof_pair(seal, Some(controller))
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "managed Agent PCR Seal head has no controller-device verification method"
            )
        })?;
    match crate::identity::device_directory::cached_device_signing_key(&actor, &device) {
        crate::identity::device_directory::CacheLookup::Hit(_) => Ok(()),
        crate::identity::device_directory::CacheLookup::NegativeHit => anyhow::bail!(
            "managed Agent PCR Seal head device key is revoked or unavailable for {actor}#{device}"
        ),
        crate::identity::device_directory::CacheLookup::Miss => {
            let resolved = resolve(actor.clone(), device.clone()).await?;
            if resolved.is_none() {
                anyhow::bail!(
                    "authoritative device key unavailable for managed Agent PCR Seal head signer {actor}#{device}"
                );
            }
            if !matches!(
                crate::identity::device_directory::cached_device_signing_key(&actor, &device),
                crate::identity::device_directory::CacheLookup::Hit(_)
            ) {
                anyhow::bail!(
                    "managed Agent PCR Seal head device key resolution did not populate the verification cache for {actor}#{device}"
                );
            }
            Ok(())
        }
    }
}

/// Prime the authoritative controller-device key required to verify a managed
/// Agent PCR frontier receipt. Frontier reads are valid outside the sync loop,
/// so they must not depend on an unrelated sync pass having warmed the global
/// device-directory cache first.
/// DID-P2-B: `state_store` is the app-level accepted-binding handle.
///
/// It replaces the throw-away `DidResolutionCache::default()` this function
/// used to build. Frontier reads happen outside the sync loop, so without a
/// durable handle every call re-resolved the controller DID from scratch and
/// then discarded the result when the local `authority` dropped. The parameter
/// is threaded down from the UI call sites rather than read from a global, so
/// the account whose bindings are consulted is always the one the caller means.
pub(crate) async fn prefetch_managed_agent_pcr_seal_head_device_key<
    S: GovernanceProofStateStore,
>(
    http: &arkret_sdk::http_client::Client,
    seal: &Seal,
    controller: &arkret_sdk::Did,
    state_store: S,
) -> anyhow::Result<()> {
    let binding_scope = crate::identity::did_binding::DidBindingScope::for_server(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        http.base_url().as_str(),
    )
    .map_err(|error| anyhow::anyhow!("resolver policy digest: {error}"))?;
    let authority = crate::identity::did_resolver::ResolverDidAnchor::from_persisted_bindings(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        arkret_sdk::identity::DidResolutionCache::default(),
        binding_scope,
        arkret_sdk::identity::DidBindingPurpose::DeviceSigner,
        state_store.with_read(crate::state::LocalStateStore::accepted_did_bindings),
    );
    let result = {
        let authority = &authority;
        ensure_managed_agent_pcr_seal_head_device_key_with(
            seal,
            controller,
            |actor, device| async move {
                crate::identity::device_directory::resolve_device_signing_key_with_http(
                    http, authority, &actor, &device,
                )
                .await
            },
        )
        .await
    };
    // Persist whatever was accepted even when the verdict below fails: an
    // acceptance is a completed authority verification and re-doing it on the
    // next attempt would be a gratuitous extra network call.
    if let (_, Some(records)) = authority.into_cache_and_bindings() {
        state_store.with_write(|store| store.store_accepted_did_bindings(records));
    }
    result
}

fn delegated_device_verification_method_pair(
    verification_method: &str,
    delegated_controller: Option<&arkret_sdk::Did>,
) -> Result<Option<(String, String)>, String> {
    let signer = verification_method_did(verification_method)
        .map_err(|error| format!("invalid Seal verification method: {error}"))?;
    if delegated_controller != Some(&signer) {
        return Ok(None);
    }
    let Some(fragment) = verification_method
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
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
    trusted_anchor: &arkret_sdk::SealId,
    resolver: &R,
) -> Result<arkret_sdk::VerifiedMlsGovernanceProof, String>
where
    R: DidResolver,
{
    verify_request_binding(request, &bundle.governance_binding)?;
    let notary = target_notary_value(bundle)?;
    let delegated_controller = managed_agent_pcr_delegated_controller(bundle, &notary)?;
    arkret_sdk::verify_mls_governance_proof_bundle(
        bundle,
        &bundle.governance_binding,
        trusted_anchor,
        |seal| verify_seal(seal, &notary, delegated_controller.as_ref(), resolver),
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
                    crate::identity::device_directory::verify_proof_value_for_signer_result(
                        &envelope,
                        &proof_value,
                        &actor,
                        event.actor_id.as_str(),
                        &key,
                    )
                    .map_err(|error| {
                        arkret_sdk::Error::Protocol(format!(
                            "MLS governance frontier Event device proof is invalid: {error}"
                        ))
                    })?;
                } else {
                    // Governance bundles replay already-accepted durable Events as historical
                    // evidence. Their admission path enforced freshness/replay resistance when
                    // the Event was submitted; re-verification here must keep validating the
                    // immutable signature after the transient five-minute presentation window.
                    // Device proofs above intentionally have the same durable semantics.
                    let mut context = arkret_sdk::event_proof_verification_context(event)?;
                    context.replay_window = chrono::Duration::MAX;
                    let verified = arkret_sdk::verify_event_proof_with_did_resolver_context(
                        event, proof, resolver, context,
                    )?;
                    if !verified.valid {
                        return Err(arkret_sdk::Error::Protocol(
                            "MLS governance frontier Event proof is invalid".to_owned(),
                        ));
                    }
                }
            }
            Ok(())
        },
        // `arkret-state` must not depend on `arkret-schema` (tools/check-layering),
        // so the registry projection is injected instead of linked. Routing it
        // through the one client evaluator keeps the cells the bundle is checked
        // against identical to the cells the receiver derives.
        |event| {
            crate::operation::project_registered_cell_writes(event)
                .map(|writes| writes.into_iter().map(|write| write.cell).collect())
                .map_err(|error| {
                    arkret_sdk::Error::Protocol(format!(
                        "MLS governance frontier Event cell projection failed: {error}"
                    ))
                })
        },
    )
    .map_err(|error| format!("verify MLS governance proof: {error}"))
}

pub(crate) fn cached_verified_binding(
    state_store: &crate::state::LocalStateStore,
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
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
    let anchor = arkret_sdk::SealId::new(
        "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    state_store
        .pin_mls_governance_anchor(realm_id, &anchor)
        .unwrap();
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
        arkret_wire::ScopeRef::Realm { realm_id } => {
            arkret_sdk::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                request.mls_group_id.clone(),
                previous_epoch,
                next_epoch,
                frontier,
                vec![anchor.clone()],
                root.clone(),
                root.clone(),
                root,
                request.binding_profile.clone(),
                request.reducer_profile.clone(),
            )
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_sdk::MlsGovernanceBindingPayload::circle(
            realm_id.clone(),
            circle_id.clone(),
            request.mls_group_id.clone(),
            previous_epoch,
            next_epoch,
            frontier,
            vec![anchor.clone()],
            root.clone(),
            root.clone(),
            root,
            request.binding_profile.clone(),
            request.reducer_profile.clone(),
        ),
        _ => panic!("unsupported effective scope in MLS governance test fixture"),
    }
    .unwrap();
    let bundle = arkret_sdk::MaterializedMlsGovernanceProofBundle {
        bundle_version: arkret_sdk::MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
        proof_request_digest: request.proof_request_digest().unwrap(),
        bundle_digest: arkret_sdk::Hash::new(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap(),
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
        .cache_verified_mls_governance_proof(request, &bundle)
        .unwrap();
    binding
}

fn verify_request_binding(
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
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
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
) -> Result<arkret_sdk::NotaryValue, String> {
    let expected = arkret_wire::null_subject_cell("ak.component.notary.v1");
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
    } else if matches!(bundle.effective_scope, arkret_wire::ScopeRef::Realm { .. }) {
        return Err("Realm-scoped MLS governance proof omits its genesis Event".to_owned());
    }
    Ok(notary)
}

fn managed_agent_pcr_delegated_controller(
    bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
    notary: &arkret_sdk::NotaryValue,
) -> Result<Option<arkret_sdk::Did>, String> {
    let managed = bundle
        .frontier_events
        .iter()
        .filter(|event| {
            event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE
                && event.executed_by.is_some()
                && event
                    .payload
                    .get("object")
                    .and_then(|object| object.get("fields"))
                    .and_then(|fields| fields.get("purpose"))
                    .and_then(serde_json::Value::as_str)
                    == Some("principal_control")
        })
        .collect::<Vec<_>>();
    if managed.is_empty() {
        return Ok(None);
    }
    if managed.len() != 1 {
        return Err(
            "MLS governance proof contains an ambiguous managed Agent PCR genesis".to_owned(),
        );
    }
    let create = managed[0];
    // v1 carries no producer effect set to compare against. The equivalent
    // check is that the registered contract projects the canonical four
    // genesis cells for this create — which `materialize_managed_agent_pcr_control`
    // asserts through the same injected evaluator the receiver uses.
    arkret_bootstrap::materialize_managed_agent_pcr_control(
        std::slice::from_ref(create),
        &crate::operation::cell_write_projector,
    )
    .map_err(|error| format!("managed Agent PCR genesis is not canonical: {error}"))?;
    if create.realm_id != bundle.realm_id
        || create
            .payload
            .get("object")
            .and_then(|object| object.get("created_by"))
            .and_then(serde_json::Value::as_str)
            != Some(create.actor_id.as_str())
        || create
            .payload
            .get("object")
            .and_then(|object| object.get("fields"))
            .and_then(|fields| fields.get("purpose"))
            .and_then(serde_json::Value::as_str)
            != Some("principal_control")
        || !notary.includes_signer_as_primary(&create.actor_id)
    {
        return Err(
            "managed Agent PCR genesis does not bind its Agent actor, Realm, and notary".to_owned(),
        );
    }
    let controller = create
        .executed_by
        .clone()
        .ok_or_else(|| "managed Agent PCR genesis omits its delegated controller".to_owned())?;
    let authorization_ref = create.authorization_ref.as_deref().ok_or_else(|| {
        "managed Agent PCR genesis omits its controller authorization_ref".to_owned()
    })?;
    if controller == create.actor_id
        || authorization_ref != format!("{}#managed-controller", create.actor_id)
    {
        return Err(
            "managed Agent PCR genesis has an invalid controller delegation binding".to_owned(),
        );
    }
    Ok(Some(controller))
}

fn verify_seal<R>(
    seal: &Seal,
    notary: &arkret_sdk::NotaryValue,
    delegated_controller: Option<&arkret_sdk::Did>,
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
    if !notary.includes_signer_as_primary(&signer) && delegated_controller != Some(&signer) {
        return Err(arkret_sdk::Error::Protocol(format!(
            "Seal signer {signer} is not authorized by the materialized Realm notary cell"
        )));
    }
    if let Some((actor, device)) = managed_seal_device_proof_pair(seal, delegated_controller)
        .map_err(arkret_sdk::Error::Protocol)?
    {
        let key = match crate::identity::device_directory::cached_device_signing_key(
            &actor, &device,
        ) {
            crate::identity::device_directory::CacheLookup::Hit(key) => key,
            crate::identity::device_directory::CacheLookup::NegativeHit => {
                return Err(arkret_sdk::Error::Protocol(format!(
                    "MLS governance Seal controller device key is revoked or unavailable for {actor}#{device}"
                )));
            }
            crate::identity::device_directory::CacheLookup::Miss => {
                return Err(arkret_sdk::Error::Protocol(format!(
                    "MLS governance Seal controller device key was not prefetched for {actor}#{device}"
                )));
            }
        };
        return arkret_sdk::signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(&signature.jws, &canonical_bytes, &key)
            .map_err(|error| {
                arkret_sdk::Error::Protocol(format!(
                    "Seal controller device signature invalid: {error}"
                ))
            });
    }
    // DID-P2-B / spec §3+§6: this is ordinary per-signature verification, not an
    // authority trigger. `resolver` here is the in-memory
    // [`StaticProofDidResolver`] the caller pre-populated with already
    // authority-resolved documents, so the correct API is the pinned-document
    // verifier, which holds no network resolver at all and additionally
    // compares `document.id == issuer` (the deprecated `verify_jws_ed25519`
    // accepted an `issuer` argument and never compared it).
    let document = resolver.resolve_did(&signer).map_err(|error| {
        arkret_sdk::Error::Protocol(format!("Seal signer document unavailable: {error}"))
    })?;
    arkret_identity::verify_jws_with_document(
        &canonical_bytes,
        &signature.jws,
        &signature.verification_method,
        &signer,
        &document,
    )
    .map_err(|error| arkret_sdk::Error::Protocol(format!("Seal signature invalid: {error}")))
}

/// Verify a managed Agent PCR frontier receipt before it is trusted as the
/// predecessor for a controller-authored successor Seal.
pub(crate) fn verify_managed_agent_pcr_seal_head(
    seal: &Seal,
    controller: &arkret_sdk::Did,
) -> arkret_sdk::Result<()> {
    seal.validate_structural()?;
    seal.validate_id()?;
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    let signature = match &seal.notary_signature {
        NotarySig::Single(signature) => signature,
        NotarySig::Multi(_) | NotarySig::Threshold(_) => {
            return Err(arkret_sdk::Error::Protocol(
                "managed Agent PCR Seal head requires one controller-device signature".to_owned(),
            ));
        }
    };
    if signature.alg != "EdDSA" {
        return Err(arkret_sdk::Error::Protocol(
            "managed Agent PCR Seal head signature must use EdDSA".to_owned(),
        ));
    }
    let signer = verification_method_did(&signature.verification_method)?;
    if &signer != controller {
        return Err(arkret_sdk::Error::Protocol(format!(
            "managed Agent PCR Seal head signer {signer} is not controller {controller}"
        )));
    }
    let (actor, device) = managed_seal_device_proof_pair(seal, Some(controller))
        .map_err(arkret_sdk::Error::Protocol)?
        .ok_or_else(|| {
            arkret_sdk::Error::Protocol(
                "managed Agent PCR Seal head has no controller-device verification method"
                    .to_owned(),
            )
        })?;
    let key = match crate::identity::device_directory::cached_device_signing_key(&actor, &device) {
        crate::identity::device_directory::CacheLookup::Hit(key) => key,
        crate::identity::device_directory::CacheLookup::NegativeHit => {
            return Err(arkret_sdk::Error::Protocol(format!(
                "managed Agent PCR Seal head device key is revoked or unavailable for {actor}#{device}"
            )));
        }
        crate::identity::device_directory::CacheLookup::Miss => {
            return Err(arkret_sdk::Error::Protocol(format!(
                "managed Agent PCR Seal head device key was not prefetched for {actor}#{device}"
            )));
        }
    };
    arkret_sdk::signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&signature.jws, &canonical_bytes, &key)
        .map_err(|error| {
            arkret_sdk::Error::Protocol(format!(
                "managed Agent PCR Seal head controller-device signature invalid: {error}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_path(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("inkson-{name}-{stamp}.json"))
    }

    fn frontier_event(actor: &str) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            "ak.member.state",
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
            },
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
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned()).unwrap(),
            event_digest: arkret_sdk::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            )
            .unwrap(),
            created_at: chrono::Utc::now(),
            domain: None,
            audience: None,
            proof_purpose: None,
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
    fn delegated_frontier_event_uses_executor_device_directory_pair() {
        let actor = "did:webvh:zfixture:agent.example";
        let controller = "did:webvh:zfixture:controller.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let mut event = frontier_event(actor);
        event.executed_by = Some(arkret_sdk::Did::new(controller.to_owned()).unwrap());

        assert_eq!(
            event_device_proof_pair(&event, &proof(&format!("{controller}#{device}")),).unwrap(),
            Some((controller.to_owned(), device.to_owned()))
        );
    }

    #[test]
    fn managed_seal_controller_device_uses_device_directory_pair() {
        let controller =
            arkret_sdk::Did::new("did:webvh:zfixture:controller.example".to_owned()).unwrap();
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";

        assert_eq!(
            delegated_device_verification_method_pair(
                &format!("{controller}#{device}"),
                Some(&controller),
            )
            .unwrap(),
            Some((controller.as_str().to_owned(), device.to_owned()))
        );
    }

    #[test]
    fn managed_seal_non_controller_stays_on_notary_authority_path() {
        let controller =
            arkret_sdk::Did::new("did:webvh:zfixture:controller.example".to_owned()).unwrap();

        assert_eq!(
            delegated_device_verification_method_pair(
                "did:webvh:zfixture:notary.example#ak:device:01904100-0000-7000-8000-0000000000a1",
                Some(&controller),
            )
            .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn managed_seal_head_cold_cache_resolves_device_key_before_verification() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use ed25519_dalek::SigningKey;

        let controller =
            arkret_sdk::Did::new("did:webvh:zfixture:cold-cache-controller.example".to_owned())
                .unwrap();
        let device = "ak:device:01904100-0000-7000-8000-0000000000c1";
        let root = arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
        let seal = arkret_sdk::Seal {
            id: arkret_sdk::SealId::new(format!("ak:seal:{root}")).unwrap(),
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:01904100-0000-7000-8000-0000000000c1".to_owned(),
            )
            .unwrap(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: root.clone(),
            state_root: root.clone(),
            completeness_root: root.clone(),
            notary_seq: 0,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_sdk::NotarySig::Single(arkret_wire::PayloadSignature {
                alg: "EdDSA".to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!("{controller}#{device}"))
                    .unwrap(),
                payload_digest: root,
                created_at: chrono::Utc::now(),
                jws: "AAAA..BBBB".to_owned(),
                extra: Default::default(),
            }),
            sealed_at: chrono::Utc::now(),
            hlc: arkret_sdk::Hlc::new("01980b44cc01-0000-aabbccdd").unwrap(),
            kind: arkret_sdk::SealKind::Compaction,
        };
        crate::identity::device_directory::invalidate(controller.as_str(), device);
        let key = arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[91; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_resolver = Arc::clone(&calls);
        let key_for_resolver = key.clone();
        let expected_controller = controller.to_string();

        ensure_managed_agent_pcr_seal_head_device_key_with(
            &seal,
            &controller,
            move |resolved_actor, resolved_device| async move {
                calls_for_resolver.fetch_add(1, Ordering::SeqCst);
                assert_eq!(resolved_actor, expected_controller);
                assert_eq!(resolved_device, device);
                crate::identity::device_directory::seed_positive_for_test(
                    &resolved_actor,
                    &resolved_device,
                    key_for_resolver.clone(),
                );
                Ok::<_, anyhow::Error>(Some(key_for_resolver))
            },
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            crate::identity::device_directory::cached_device_signing_key(
                "did:webvh:zfixture:cold-cache-controller.example",
                device,
            ),
            crate::identity::device_directory::CacheLookup::Hit(_)
        ));
        crate::identity::device_directory::invalidate(
            "did:webvh:zfixture:cold-cache-controller.example",
            device,
        );
    }

    #[test]
    fn only_bottom_projection_conflicts_are_retryable() {
        let pending = arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(
                "state_mismatch",
                "member cell is still Bottom",
            )),
        };
        let policy_denial = arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(arkret_sdk::ErrorEnvelope::new(
                "state_mismatch",
                "governance policy digest differs",
            )),
        };

        assert!(governance_projection_pending(&pending));
        assert!(!governance_projection_pending(&policy_denial));
        assert!(!governance_projection_pending(
            &arkret_sdk::http_client::Error::Protocol("member cell is still Bottom".to_owned(),)
        ));
    }

    #[test]
    fn incomplete_chunk_acquisition_survives_state_store_restart() {
        let path = temp_state_path("mls-governance-acquisition");
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let request;
        let expected_chunk;
        {
            let mut writer = crate::state::LocalStateStore::with_path(path.clone());
            let anchor = arkret_sdk::SealId::new(
                "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap();
            writer.pin_mls_governance_anchor(realm_id, &anchor).unwrap();
            seed_test_governance_proof(&mut writer, realm_id, None, "dGVzdC1tbHM", 0, 1);
            request = proof_request(&writer, realm_id, None, "dGVzdC1tbHM", 0, 1).unwrap();
            let mut materialized = writer
                .cached_mls_governance_proof(&request, chrono::Utc::now())
                .unwrap()
                .expect("seeded materialized proof");
            let root = arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
            materialized.seal_path = vec![arkret_sdk::Seal {
                id: anchor.clone(),
                realm_id: request.realm_id.clone(),
                predecessor_refs: Vec::new(),
                delta: Vec::new(),
                control_event_set_root: root.clone(),
                state_root: root.clone(),
                completeness_root: root.clone(),
                notary_seq: 0,
                data_view_root: None,
                data_event_set_root: None,
                availability_root: None,
                coverage_scope: None,
                covered_event_digests: Vec::new(),
                previous_state_root: None,
                previous_digest_algorithm: None,
                notary_signature: arkret_sdk::NotarySig::Single(arkret_wire::PayloadSignature {
                    alg: "EdDSA".to_owned(),
                    verification_method: arkret_sdk::DidUrl::new("did:web:notary.example#key-1")
                        .unwrap(),
                    payload_digest: root,
                    created_at: chrono::Utc::now(),
                    jws: "AAAA.BBBB.CCCC".to_owned(),
                    extra: Default::default(),
                }),
                sealed_at: chrono::Utc::now(),
                hlc: arkret_sdk::Hlc::new("01980b44cc01-0000-aabbccdd").unwrap(),
                kind: arkret_sdk::SealKind::Compaction,
            }];
            materialized.frontier_events = vec![frontier_event("did:webvh:zfixture:alice.example")];
            expected_chunk = arkret_sdk::build_mls_governance_proof_chunks(&request, &materialized)
                .unwrap()
                .remove(0);
            writer
                .persist_mls_governance_acquisition_chunk(&request, &expected_chunk)
                .unwrap();
        }

        let reader = crate::state::LocalStateStore::with_path(path.clone());
        let resumed = reader
            .cached_mls_governance_acquisition(&request)
            .expect("restart reloads incomplete acquisition");
        assert_eq!(
            serde_json::to_value(&resumed).unwrap(),
            serde_json::to_value([expected_chunk]).unwrap()
        );
        let _ = std::fs::remove_file(path);
    }
}
