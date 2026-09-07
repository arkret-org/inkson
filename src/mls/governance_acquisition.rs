use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_sdk::http_client;

const MAX_EVENT_BATCH: usize = 128;
const MAX_DEPENDENCY_BATCH: usize = 8;
type DependencySortKey = (String, Vec<u8>);

pub(crate) struct ResolvedMlsGovernanceProof {
    pub(crate) bundle: arkret_sdk::MlsGovernanceProofBundle,
    pub(crate) seals: Vec<arkret_sdk::Seal>,
    pub(crate) delta_events: Vec<arkret_sdk::Event>,
    pub(crate) provenance_events: Vec<arkret_sdk::Event>,
    pub(crate) dependencies: Vec<arkret_sdk::GovernanceDependency>,
}

pub(crate) struct ResolvedMlsGovernanceCut {
    pub(crate) target_basis: arkret_sdk::SealBasis,
    pub(crate) seals: Vec<arkret_sdk::Seal>,
    pub(crate) events: Vec<arkret_sdk::Event>,
    pub(crate) dependencies: Vec<arkret_sdk::GovernanceDependency>,
}

pub(crate) async fn resolve_mls_governance_checkpoint(
    api: &crate::transport::TransportClient,
    realm_id: &arkret_sdk::RealmId,
    target_basis: &arkret_sdk::SealBasis,
) -> Result<ResolvedMlsGovernanceCut, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance checkpoint client: {error}"))?;
    resolve_mls_governance_checkpoint_with_http(&http, realm_id, target_basis).await
}

pub(crate) async fn resolve_mls_governance_checkpoint_with_http(
    http: &arkret_sdk::http_client::Client,
    realm_id: &arkret_sdk::RealmId,
    target_basis: &arkret_sdk::SealBasis,
) -> Result<ResolvedMlsGovernanceCut, String> {
    target_basis
        .validate_protocol_bounds()
        .map_err(|error| format!("invalid MLS governance checkpoint target: {error}"))?;
    let mut seals = BTreeMap::new();
    let mut pending = target_basis.leaves.iter().cloned().collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        let batch = pending
            .iter()
            .take(arkret_sdk::MAX_SEAL_RESOLVE_SELECTORS)
            .cloned()
            .collect::<Vec<_>>();
        for seal_ref in &batch {
            pending.remove(seal_ref);
        }
        for seal in fetch_seals_for_realm(http, realm_id, batch).await? {
            for predecessor in &seal.predecessor_refs {
                if !seals.contains_key(predecessor) {
                    pending.insert(predecessor.clone());
                }
            }
            if seals.insert(seal.id.clone(), seal).is_some() {
                return Err("MLS governance checkpoint Seal closure contains duplicates".to_owned());
            }
        }
    }
    let event_digests = seals
        .values()
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let events =
        fetch_event_set(http, &event_digests, &BTreeMap::new(), "checkpoint delta").await?;
    let seal_values = seals.into_values().collect::<Vec<_>>();
    let selectors = arkret_sdk::governance_runtime_dependency_selector_coordinates_for_acquisition(
        &seal_values,
        &events,
    )
    .map_err(|error| format!("discover MLS governance checkpoint dependencies: {error}"))?;
    let dependencies = fetch_dependency_closure_for_realm(http, realm_id, selectors)
        .await?
        .into_values()
        .collect();
    Ok(ResolvedMlsGovernanceCut {
        target_basis: target_basis.clone(),
        seals: seal_values,
        events,
        dependencies,
    })
}

pub(crate) async fn resolve_mls_governance_proof(
    api: &crate::transport::TransportClient,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    base_checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
) -> Result<ResolvedMlsGovernanceProof, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance proof client: {error}"))?;
    let bundle = fetch_proof_with_retry(&http, request).await?;

    let mut seals_by_id = base_checkpoint
        .accepted_seals
        .iter()
        .cloned()
        .map(|seal| (seal.id.clone(), seal))
        .collect::<BTreeMap<_, _>>();
    let requested_seals = bundle
        .proof_material
        .seal_descriptors
        .iter()
        .map(|descriptor| descriptor.seal_ref.clone())
        .collect::<Vec<_>>();
    let missing_seals = requested_seals
        .iter()
        .filter(|seal_ref| !seals_by_id.contains_key(*seal_ref))
        .cloned()
        .collect::<Vec<_>>();
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .cloned()
        .ok_or_else(|| "MLS governance proof scope has no Realm".to_owned())?;
    for seal in fetch_seals_for_realm(&http, &realm_id, missing_seals).await? {
        if seals_by_id.insert(seal.id.clone(), seal).is_some() {
            return Err("Seal resolver returned a duplicate checkpoint Seal".to_owned());
        }
    }
    let seals = requested_seals
        .iter()
        .map(|seal_ref| {
            seals_by_id
                .get(seal_ref)
                .cloned()
                .ok_or_else(|| format!("MLS governance proof omitted resolved Seal {seal_ref}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let base = request
        .proof_base_basis
        .leaves
        .iter()
        .collect::<BTreeSet<_>>();
    let delta_digests = seals
        .iter()
        .filter(|seal| !base.contains(&seal.id))
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let provenance_digests = bundle
        .proof_material
        .event_ids
        .iter()
        .map(arkret_sdk::EventId::event_digest)
        .collect::<BTreeSet<_>>();
    let checkpoint_events = base_checkpoint
        .accepted_events
        .iter()
        .map(|event| event_with_digest_claim(event).map(|digest| (digest, event.clone())))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let delta_events =
        fetch_event_set(&http, &delta_digests, &checkpoint_events, "Seal delta").await?;
    let provenance_events = fetch_event_set(
        &http,
        &provenance_digests,
        &checkpoint_events,
        "frontier provenance",
    )
    .await?;

    let replay_events = delta_events
        .iter()
        .chain(provenance_events.iter())
        .cloned()
        .collect::<Vec<_>>();
    let selectors = arkret_sdk::governance_runtime_dependency_selector_coordinates_for_acquisition(
        &seals,
        &replay_events,
    )
    .map_err(|error| format!("discover MLS governance dependencies: {error}"))?;
    let dependencies = fetch_dependency_closure(&http, request, selectors).await?;

    let dependencies = dependencies.into_values().collect::<Vec<_>>();
    Ok(ResolvedMlsGovernanceProof {
        bundle,
        seals,
        delta_events,
        provenance_events,
        dependencies,
    })
}

pub(crate) async fn resolve_history_governance_cut(
    api: &crate::transport::TransportClient,
    retention: &arkret_sdk::HistoryGovernanceTraversalRetention,
    access: Option<&arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<ResolvedMlsGovernanceCut, String> {
    retention
        .validate_digest()
        .map_err(|error| format!("invalid retained governance traversal: {error}"))?;
    let (effective_scope, base_basis, target_basis) = match &retention.traversal_intent {
        arkret_sdk::HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
            effective_scope,
            trusted_history_base_basis,
            target_basis,
            ..
        }
        | arkret_sdk::HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            effective_scope,
            trusted_history_base_basis,
            target_basis,
            ..
        } => (effective_scope, trusted_history_base_basis, target_basis),
    };
    let realm_id = match effective_scope {
        arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
        | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id.clone(),
    };
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build retained governance traversal client: {error}"))?;
    let base_leaves = base_basis.leaves.iter().cloned().collect::<BTreeSet<_>>();
    let mut pending = target_basis
        .leaves
        .iter()
        .filter(|seal_ref| !base_leaves.contains(*seal_ref))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut seals = BTreeMap::new();
    while !pending.is_empty() {
        let batch = pending
            .iter()
            .take(arkret_sdk::MAX_SEAL_RESOLVE_SELECTORS)
            .cloned()
            .collect::<Vec<_>>();
        for seal_ref in &batch {
            pending.remove(seal_ref);
        }
        for seal in
            fetch_seals_for_realm_with_access(&http, &realm_id, batch, access.cloned()).await?
        {
            for predecessor in &seal.predecessor_refs {
                if !base_leaves.contains(predecessor) && !seals.contains_key(predecessor) {
                    pending.insert(predecessor.clone());
                }
            }
            if seals.insert(seal.id.clone(), seal).is_some() {
                return Err("retained governance cut contains duplicate Seals".to_owned());
            }
        }
    }
    let seals = seals.into_values().collect::<Vec<_>>();
    let event_digests = seals
        .iter()
        .flat_map(|seal| seal.delta.iter().cloned())
        .collect::<BTreeSet<_>>();
    let events = fetch_event_set_with_access(
        &http,
        &event_digests,
        &BTreeMap::new(),
        "retained cut delta",
        access.cloned(),
    )
    .await?;
    let selectors = arkret_sdk::governance_runtime_dependency_selector_coordinates_for_acquisition(
        &seals, &events,
    )
    .map_err(|error| format!("discover retained governance dependencies: {error}"))?;
    let dependencies = fetch_dependency_closure_for_realm_with_access(
        &http,
        &realm_id,
        selectors,
        access.cloned(),
    )
    .await?
    .into_values()
    .collect();
    Ok(ResolvedMlsGovernanceCut {
        target_basis: target_basis.clone(),
        seals,
        events,
        dependencies,
    })
}

pub(crate) async fn resolve_history_response_signer_dependencies(
    api: &crate::transport::TransportClient,
    realm_id: &arkret_sdk::RealmId,
    request_receipt_digest: &arkret_sdk::Hash,
    source_evidence_digests: impl IntoIterator<Item = arkret_sdk::Hash>,
    release_service_evidence_digests: impl IntoIterator<Item = arkret_sdk::Hash>,
) -> Result<Vec<arkret_sdk::GovernanceDependency>, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build history signer-evidence client: {error}"))?;
    let source_evidence_digests = source_evidence_digests.into_iter().collect::<Vec<_>>();
    let mut selectors = Vec::new();
    for content_digest in &source_evidence_digests {
        selectors.push(
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: content_digest.clone(),
            },
        );
        selectors.push(
            arkret_sdk::GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                content_digest: content_digest.clone(),
            },
        );
    }
    let release_selectors = release_service_evidence_digests
        .into_iter()
        .map(|content_digest| {
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest,
            }
        })
        .collect::<Vec<_>>();
    let access = arkret_sdk::SelfHistoryTraversalAccess::RequestReceipt {
        request_receipt_digest: request_receipt_digest.clone(),
    };
    // A source digest identifies exactly one of the two current evidence types.
    // Discovery may report the other type missing; the selected closure may not.
    let available = fetch_available_dependency_batches_for_realm(
        &http,
        realm_id,
        selectors,
        Some(access.clone()),
    )
    .await?;
    let available_keys = available.keys().cloned().collect::<BTreeSet<_>>();
    let mut selected = select_history_source_evidence(source_evidence_digests, &available_keys)?;
    selected.extend(release_selectors);
    fetch_dependency_closure_for_realm_with_access(&http, realm_id, selected, Some(access))
        .await
        .map(|items| items.into_values().collect())
}

fn select_history_source_evidence(
    digests: Vec<arkret_sdk::Hash>,
    available: &BTreeSet<DependencySortKey>,
) -> Result<Vec<arkret_sdk::GovernanceDependencySelector>, String> {
    let mut selected = Vec::new();
    for content_digest in digests {
        let candidates = [
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: content_digest.clone(),
            },
            arkret_sdk::GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                content_digest,
            },
        ];
        let mut matches = Vec::new();
        for candidate in candidates {
            if available.contains(&selector_key(&candidate)?) {
                matches.push(candidate);
            }
        }
        if matches.len() != 1 {
            return Err(
                "history source digest must resolve to exactly one evidence type".to_owned(),
            );
        }
        selected.extend(matches);
    }
    canonical_dependency_selectors(selected)
}

async fn fetch_proof_with_retry(
    http: &arkret_sdk::Client,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
) -> Result<arkret_sdk::MlsGovernanceProofBundle, String> {
    const MAX_ATTEMPTS: u32 = 8;
    for attempt in 0..MAX_ATTEMPTS {
        match http.mls_governance_proof(request).await {
            Ok(bundle) => return Ok(bundle),
            Err(error) if attempt + 1 < MAX_ATTEMPTS && projection_pending(&error) => {
                let delay_ms = (100_u64 << attempt).min(1_000);
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(delay_ms)).await;
            }
            Err(error) => return Err(format!("fetch MLS governance proof: {error}")),
        }
    }
    unreachable!("bounded MLS governance proof retry always returns")
}

fn projection_pending(error: &http_client::Error) -> bool {
    match error {
        http_client::Error::Api { status: 409, error } => {
            error.code() == "state_mismatch" && error.detail.to_ascii_lowercase().contains("bottom")
        }
        http_client::Error::Api { status: 503, error } => {
            error.code() == arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE
        }
        _ => false,
    }
}

fn limit_exceeded(error: &http_client::Error) -> bool {
    matches!(
        error,
        http_client::Error::Api { error, .. }
            if error.code() == arkret_sdk::error_codes::ErrorCode::LIMIT_EXCEEDED
    )
}

async fn fetch_seals_for_realm(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    seal_refs: Vec<arkret_sdk::SealId>,
) -> Result<Vec<arkret_sdk::Seal>, String> {
    fetch_seals_for_realm_with_access(http, realm_id, seal_refs, None).await
}

async fn fetch_seals_for_realm_with_access(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    seal_refs: Vec<arkret_sdk::SealId>,
    history_traversal_access: Option<arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<Vec<arkret_sdk::Seal>, String> {
    let mut pending = VecDeque::new();
    for chunk in seal_refs.chunks(arkret_sdk::MAX_SEAL_RESOLVE_SELECTORS) {
        pending.push_back(chunk.to_vec());
    }
    let mut seals = BTreeMap::new();
    while let Some(batch) = pending.pop_front() {
        if batch.is_empty() {
            continue;
        }
        let resolve = arkret_sdk::SelfSealResolveRequestBody {
            realm_id: realm_id.clone(),
            seal_refs: batch.clone(),
            history_traversal_access: history_traversal_access.clone(),
        };
        match http.seals_resolve(&resolve).await {
            Ok(outcome) => {
                if !outcome.missing_seal_refs.is_empty() {
                    return Err("MLS governance Seal resolution is incomplete".to_owned());
                }
                for seal in outcome.seals {
                    if seals.insert(seal.id.clone(), seal).is_some() {
                        return Err("MLS governance Seal resolution returned duplicates".to_owned());
                    }
                }
            }
            Err(error) if limit_exceeded(&error) && batch.len() > 1 => {
                let right = batch.len() / 2;
                pending.push_front(batch[right..].to_vec());
                pending.push_front(batch[..right].to_vec());
            }
            Err(error) if limit_exceeded(&error) => {
                return Err("one canonical Seal exceeds the 8 MiB resolve ceiling".to_owned());
            }
            Err(error) => return Err(format!("resolve MLS governance Seals: {error}")),
        }
    }
    Ok(seals.into_values().collect())
}

async fn fetch_event_set(
    http: &arkret_sdk::Client,
    expected: &BTreeSet<arkret_sdk::Hash>,
    checkpoint: &BTreeMap<arkret_sdk::Hash, arkret_sdk::Event>,
    label: &str,
) -> Result<Vec<arkret_sdk::Event>, String> {
    fetch_event_set_with_access(http, expected, checkpoint, label, None).await
}

async fn fetch_event_set_with_access(
    http: &arkret_sdk::Client,
    expected: &BTreeSet<arkret_sdk::Hash>,
    checkpoint: &BTreeMap<arkret_sdk::Hash, arkret_sdk::Event>,
    label: &str,
    history_traversal_access: Option<arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<Vec<arkret_sdk::Event>, String> {
    let mut events = expected
        .iter()
        .filter_map(|digest| {
            checkpoint
                .get(digest)
                .cloned()
                .map(|event| (digest.clone(), event))
        })
        .collect::<BTreeMap<_, _>>();
    let missing = expected
        .iter()
        .filter(|digest| !events.contains_key(*digest))
        .cloned()
        .collect::<Vec<_>>();
    let mut pending = VecDeque::new();
    for chunk in missing.chunks(MAX_EVENT_BATCH) {
        pending.push_back(chunk.to_vec());
    }
    while let Some(batch) = pending.pop_front() {
        let resolve = arkret_sdk::EventsResolveRequestBody {
            event_ids: Vec::new(),
            event_digests: batch.clone(),
            include_payload: Some(true),
            history_traversal_access: history_traversal_access.clone(),
            max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
        };
        // A just-accepted membership Event and its Realm policy can reach the
        // durable Event log before the membership-gated read projection. In
        // that bounded convergence window, resolve correctly reports the
        // checkpoint delta as missing/unauthorized. Retry the same closed
        // selector set; never accept a partial response and never widen the
        // caller's history traversal authority.
        const PROJECTION_ATTEMPTS: usize = 20;
        let mut projection_attempt = 0;
        let outcome = loop {
            let outcome = http.events_resolve(&resolve).await;
            let retry = matches!(
                &outcome,
                Ok(outcome)
                    if (!outcome.missing.is_empty() || !outcome.unauthorized.is_empty())
                        && projection_attempt + 1 < PROJECTION_ATTEMPTS
            );
            if !retry {
                break outcome;
            }
            projection_attempt += 1;
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(250)).await;
        };
        match outcome {
            Ok(outcome) => {
                if !outcome.missing.is_empty() || !outcome.unauthorized.is_empty() {
                    return Err(format!(
                        "MLS governance {label} Event resolution is incomplete: missing={}, unauthorized={}, requested={}",
                        outcome.missing.len(),
                        outcome.unauthorized.len(),
                        batch.len(),
                    ));
                }
                let requested = batch.iter().collect::<BTreeSet<_>>();
                let mut returned = BTreeSet::new();
                for event in outcome.events {
                    let digest = event_with_digest_claim(&event)?;
                    if !requested.contains(&digest)
                        || arkret_sdk::EventId::from_event_digest(&digest)
                            .map_err(|error| format!("retype Event digest: {error}"))?
                            != event.event_id
                        || !returned.insert(digest.clone())
                        || events.insert(digest, event).is_some()
                    {
                        return Err(format!(
                            "MLS governance {label} Event outcome is not every-and-only the request"
                        ));
                    }
                }
                if returned.len() != batch.len() {
                    return Err(format!(
                        "MLS governance {label} Event resolution is incomplete: returned={}, requested={}",
                        returned.len(),
                        batch.len(),
                    ));
                }
            }
            Err(error) if limit_exceeded(&error) && batch.len() > 1 => {
                let right = batch.len() / 2;
                pending.push_front(batch[right..].to_vec());
                pending.push_front(batch[..right].to_vec());
            }
            Err(error) if limit_exceeded(&error) => {
                return Err(format!(
                    "one canonical {label} Event exceeds the 8 MiB resolve ceiling"
                ));
            }
            Err(error) => return Err(format!("resolve MLS governance {label} Events: {error}")),
        }
    }
    if events.keys().collect::<BTreeSet<_>>() != expected.iter().collect::<BTreeSet<_>>() {
        return Err(format!("MLS governance {label} Event set mismatch"));
    }
    Ok(events.into_values().collect())
}

fn event_with_digest_claim(event: &arkret_sdk::Event) -> Result<arkret_sdk::Hash, String> {
    let digest = arkret_sdk::signed_event_digest_claim(event)
        .map_err(|error| format!("read signed Event digest claim: {error}"))?;
    if arkret_sdk::EventId::from_event_digest(&digest)
        .map_err(|error| format!("retype accepted Event digest: {error}"))?
        != event.event_id
    {
        return Err("accepted Event id does not bind its canonical content".to_owned());
    }
    Ok(digest)
}

async fn fetch_dependency_closure(
    http: &arkret_sdk::Client,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
) -> Result<BTreeMap<DependencySortKey, arkret_sdk::GovernanceDependency>, String> {
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance proof scope has no Realm".to_owned())?;
    fetch_dependency_closure_for_realm(http, realm_id, selectors).await
}

async fn fetch_dependency_closure_for_realm(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
) -> Result<BTreeMap<DependencySortKey, arkret_sdk::GovernanceDependency>, String> {
    fetch_dependency_closure_for_realm_with_access(http, realm_id, selectors, None).await
}

async fn fetch_dependency_closure_for_realm_with_access(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
    history_traversal_access: Option<arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<BTreeMap<DependencySortKey, arkret_sdk::GovernanceDependency>, String> {
    let mut dependencies = fetch_dependency_batches_for_realm(
        http,
        realm_id,
        selectors,
        history_traversal_access.clone(),
    )
    .await?;
    loop {
        let material = dependencies.values().cloned().collect::<Vec<_>>();
        let next = arkret_sdk::governance_transitive_signer_evidence_selectors(&material)
            .map_err(|error| format!("discover governance attester evidence: {error}"))?
            .into_iter()
            .filter(|selector| {
                selector_key(selector)
                    .map(|key| !dependencies.contains_key(&key))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        if next.is_empty() {
            return Ok(dependencies);
        }
        dependencies.extend(
            fetch_dependency_batches_for_realm(
                http,
                realm_id,
                next,
                history_traversal_access.clone(),
            )
            .await?,
        );
    }
}

async fn fetch_dependency_batches_for_realm(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
    history_traversal_access: Option<arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<BTreeMap<DependencySortKey, arkret_sdk::GovernanceDependency>, String> {
    let selectors = canonical_dependency_selectors(selectors)?;
    let expected_count = selectors.len();
    let items = fetch_available_dependency_batches_for_realm(
        http,
        realm_id,
        selectors,
        history_traversal_access,
    )
    .await?;
    if items.len() != expected_count {
        return Err("governance dependency resolution is incomplete".to_owned());
    }
    Ok(items)
}

async fn fetch_available_dependency_batches_for_realm(
    http: &arkret_sdk::Client,
    realm_id: &arkret_sdk::RealmId,
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
    history_traversal_access: Option<arkret_sdk::SelfHistoryTraversalAccess>,
) -> Result<BTreeMap<DependencySortKey, arkret_sdk::GovernanceDependency>, String> {
    let selectors = canonical_dependency_selectors(selectors)?;
    let mut pending = VecDeque::new();
    for chunk in selectors.chunks(MAX_DEPENDENCY_BATCH) {
        pending.push_back(chunk.to_vec());
    }
    let mut items = BTreeMap::new();
    while let Some(batch) = pending.pop_front() {
        if batch.is_empty() {
            continue;
        }
        let resolve = arkret_sdk::SelfGovernanceDependencyResolveRequest {
            realm_id: realm_id.clone(),
            selectors: batch.clone(),
            byte_limit: arkret_sdk::MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES,
            history_traversal_access: history_traversal_access.clone(),
        };
        match http.governance_dependencies_resolve(&resolve).await {
            Ok(outcome) => {
                for item in outcome.items {
                    let key = selector_key(item.selector())?;
                    if items.insert(key, item).is_some() {
                        return Err("governance dependency resolver returned duplicates".to_owned());
                    }
                }
            }
            Err(error) if limit_exceeded(&error) && batch.len() > 1 => {
                let right = batch.len() / 2;
                pending.push_front(batch[right..].to_vec());
                pending.push_front(batch[..right].to_vec());
            }
            Err(error) if limit_exceeded(&error) => {
                return Err(
                    "one governance dependency exceeds the 8 MiB resolve ceiling".to_owned(),
                );
            }
            Err(error) => return Err(format!("resolve governance dependencies: {error}")),
        }
    }
    Ok(items)
}

fn canonical_dependency_selectors(
    selectors: Vec<arkret_sdk::GovernanceDependencySelector>,
) -> Result<Vec<arkret_sdk::GovernanceDependencySelector>, String> {
    let mut ordered = BTreeMap::new();
    for selector in selectors {
        ordered.insert(selector_key(&selector)?, selector);
    }
    Ok(ordered.into_values().collect())
}

fn selector_key(
    selector: &arkret_sdk::GovernanceDependencySelector,
) -> Result<DependencySortKey, String> {
    selector
        .canonical_sort_key()
        .map(|(kind, bytes)| (kind.to_owned(), bytes))
        .map_err(|error| format!("canonicalize governance dependency selector: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_source_discovery_requires_one_current_evidence_type() {
        let digest = arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let ordinary =
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: digest.clone(),
            };
        let minimal =
            arkret_sdk::GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                content_digest: digest.clone(),
            };
        for selected in [&ordinary, &minimal] {
            let available = BTreeSet::from([selector_key(selected).unwrap()]);
            assert_eq!(
                select_history_source_evidence(vec![digest.clone(), digest.clone()], &available)
                    .unwrap(),
                vec![selected.clone()]
            );
        }
        assert!(select_history_source_evidence(vec![digest.clone()], &BTreeSet::new()).is_err());
        let ambiguous = BTreeSet::from([
            selector_key(&ordinary).unwrap(),
            selector_key(&minimal).unwrap(),
        ]);
        assert!(select_history_source_evidence(vec![digest], &ambiguous).is_err());
    }

    #[test]
    fn dependency_acquisition_obeys_canonical_selector_wire_order() {
        let selector = |digit: char| {
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: arkret_sdk::Hash::new(format!(
                    "sha256:{}",
                    digit.to_string().repeat(64)
                ))
                .unwrap(),
            }
        };
        let mut request = arkret_sdk::SelfGovernanceDependencyResolveRequest {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
            )
            .unwrap(),
            selectors: vec![selector('b'), selector('a'), selector('b')],
            byte_limit: arkret_sdk::MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES,
            history_traversal_access: None,
        };
        assert!(request.validate().is_err());
        request.selectors = canonical_dependency_selectors(request.selectors).unwrap();
        assert_eq!(request.selectors, vec![selector('a'), selector('b')]);
        request.validate().unwrap();
    }
}
