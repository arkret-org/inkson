use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::identity::{DidResolver, verification_method_did};
use dioxus::prelude::{ReadableExt, WritableExt};

pub(crate) fn bind_sidecar_scope(
    base: &arkret_sdk::MlsGovernanceBindingPayload,
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> arkret_wire::Result<arkret_sdk::MlsGovernanceBindingPayload> {
    arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        base.realm_id().clone(),
        sidecar_binding.sidecar_id.clone(),
        base.mls_group_id(),
        base.previous_epoch(),
        base.next_epoch(),
        base.security_frontier_digest().clone(),
        sidecar_binding,
        base.binding_profile(),
        base.reducer_profile(),
    )
}

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
    fn supports(&self, did: &arkret_sdk::DidFullId) -> bool {
        self.documents.contains_key(did.as_str())
    }

    fn resolve_did(
        &self,
        did: &arkret_sdk::DidFullId,
    ) -> arkret_sdk::identity::Result<arkret_sdk::identity::ResolvedDid> {
        self.documents
            .get(did.as_str())
            .cloned()
            .map(arkret_sdk::identity::ResolvedDid::proofless)
            .ok_or_else(|| {
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
    local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
) -> Result<arkret_sdk::MlsGovernanceProofRequestBody, String> {
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
    proof_request_for_scope(
        state_store,
        effective_scope,
        mls_group_id,
        previous_epoch,
        next_epoch,
        local_mls_leaves,
    )
}

pub(crate) fn proof_request_for_scope(
    state_store: &crate::state::LocalStateStore,
    effective_scope: arkret_sdk::ScopeRef,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
    local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
) -> Result<arkret_sdk::MlsGovernanceProofRequestBody, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .cloned()
        .ok_or_else(|| "MLS governance proof rejects RealmGenesis scope".to_owned())?;
    let mls_group_id = arkret_sdk::Base64UrlString::new(mls_group_id.into())
        .map_err(|error| format!("invalid MLS group id: {error}"))?;
    let proof_base_basis = state_store
        .trusted_mls_governance_checkpoint(realm_id.as_str())
        .map(|checkpoint| checkpoint.basis)
        .ok_or_else(|| {
            format!(
                "MLS governance proof requires a locally verified replay checkpoint for {realm_id}; operation remains decryption_pending (state_mismatch)"
            )
        })?;
    let mut target_leaves = state_store
        .seal_view_for_realm(realm_id.as_str())
        .frontier
        .into_iter()
        .map(|seal| {
            arkret_sdk::SealId::new(seal)
                .map_err(|error| format!("invalid accepted Seal frontier id: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    target_leaves.sort();
    target_leaves.dedup();
    let proof_target_basis = arkret_sdk::SealBasis {
        leaves: target_leaves,
    };
    proof_target_basis
        .validate_protocol_bounds()
        .map_err(|error| format!("MLS governance proof has no complete target basis: {error}"))?;
    let base_group_state_ref = if previous_epoch == 0 && next_epoch == 0 {
        None
    } else {
        Some(
            state_store
                .mls_group_state_ref_for_scope(
                    &effective_scope,
                    mls_group_id.as_str(),
                    previous_epoch,
                )
                .map_err(|error| {
                    format!(
                        "MLS governance successor proof requires the accepted base group state: {error}"
                    )
                })?,
        )
    };
    let request = arkret_sdk::MlsGovernanceProofRequestBody {
        profile: arkret_sdk::MlsGovernanceProofProfile::GroupSecurityFrontier,
        effective_scope,
        mls_group_id,
        local_mls_leaves,
        proof_base_basis,
        proof_target_basis,
        byte_limit: arkret_sdk::MLS_GOVERNANCE_PROOF_MAX_BYTES,
        frontier_purpose: arkret_sdk::MlsGovernanceFrontierPurpose::GroupBinding,
        base_group_state_ref,
        previous_epoch,
        next_epoch,
        binding_profile: arkret_sdk::MlsGovernanceBindingProfile::AkSecurityFrontierV1,
    };
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    Ok(request)
}

fn group_genesis_binding(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<arkret_sdk::MlsGroupGenesisBinding, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance scope has no Realm".to_owned())?;
    let (scheme, durability) = match effective_scope {
        arkret_sdk::ScopeRef::Realm { .. } => (
            state_store.realm_content_scheme(realm_id.as_str()),
            state_store.realm_durability_policy(realm_id.as_str()),
        ),
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => (
            state_store.circle_content_scheme(realm_id.as_str(), circle_id.as_str()),
            state_store.circle_durability_policy(realm_id.as_str(), circle_id.as_str()),
        ),
        _ => return Err("unsupported MLS governance effective scope".to_owned()),
    };
    let content_scheme = match scheme.as_deref() {
        Some("mls_rfc9420") => arkret_wire::ContentScheme::MlsRfc9420,
        Some("mls_exporter_aead_v1") => arkret_wire::ContentScheme::MlsExporterAeadV1,
        Some(value) => return Err(format!("unregistered MLS content scheme {value}")),
        None => {
            return Err(
                "MLS governance proof requires the accepted create-locked content scheme"
                    .to_owned(),
            );
        }
    };
    let binding = arkret_sdk::MlsGroupGenesisBinding {
        content_scheme,
        durability_policy: durability,
    };
    binding
        .validate()
        .map_err(|error| format!("invalid MLS group genesis binding: {error}"))?;
    Ok(binding)
}

pub(crate) async fn fetch_verify_and_cache_proof<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    leaves: &[arkret_sdk::MlsSecurityFrontierLeaf],
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    fetch_verify_and_cache_proof_internal(api, state_store, request, leaves, None, None)
        .await
        .map(|(_, binding)| binding)
}

pub(crate) async fn fetch_verify_and_cache_proof_bundle<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    leaves: &[arkret_sdk::MlsSecurityFrontierLeaf],
) -> Result<arkret_sdk::MlsGovernanceProofBundle, String> {
    fetch_verify_and_cache_proof_internal(api, state_store, request, leaves, None, None)
        .await
        .map(|(bundle, _)| bundle)
}

pub(crate) async fn fetch_verify_and_cache_expected_proof<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    leaves: &[arkret_sdk::MlsSecurityFrontierLeaf],
    expected_binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    fetch_verify_and_cache_proof_internal(
        api,
        state_store,
        request,
        leaves,
        Some(expected_binding),
        None,
    )
    .await
    .map(|(_, binding)| binding)
}

async fn fetch_verify_and_cache_proof_internal<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    leaves: &[arkret_sdk::MlsSecurityFrontierLeaf],
    expected_binding: Option<&arkret_sdk::MlsGovernanceBindingPayload>,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<
    (
        arkret_sdk::MlsGovernanceProofBundle,
        arkret_sdk::MlsGovernanceBindingPayload,
    ),
    String,
> {
    if request.local_mls_leaves != leaves {
        return Err(
            "MLS governance proof request leaves differ from the locally verified group state"
                .to_owned(),
        );
    }
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance proof has no Realm scope".to_owned())?;
    let base_checkpoint = state_store
        .with_read(|store| store.trusted_mls_governance_checkpoint(realm_id.as_str()))
        .ok_or_else(|| "MLS governance proof has no locally verified base checkpoint".to_owned())?;
    if base_checkpoint.basis != request.proof_base_basis {
        return Err("MLS governance proof request base is not the pinned checkpoint".to_owned());
    }
    let resolved = crate::mls::governance_acquisition::resolve_mls_governance_proof(
        api,
        request,
        &base_checkpoint,
    )
    .await?;
    let group_genesis_binding =
        state_store.with_read(|store| group_genesis_binding(store, &request.effective_scope))?;
    let verified = arkret_sdk::verify_mls_governance_frontier(
        request,
        &resolved.bundle,
        &base_checkpoint,
        &resolved.seals,
        &resolved.delta_events,
        &resolved.provenance_events,
        &resolved.dependencies,
        &group_genesis_binding,
        leaves,
        |event, digest_suite, evidence, dependencies| {
            verify_native_agent_history_key(
                &state_store,
                event,
                digest_suite,
                evidence,
                dependencies,
            )
        },
    )
    .map_err(|error| format!("verify MLS governance frontier: {error}"))?;
    let binding = match expected_binding {
        Some(binding) => {
            verify_request_binding(request, binding)?;
            if binding.security_frontier_digest() != &verified.security_frontier_digest {
                return Err(
                    "MLS governance binding security_frontier_digest differs from the locally derived frontier"
                        .to_owned(),
                );
            }
            binding.clone()
        }
        None => binding_from_verified_frontier(
            request,
            verified.security_frontier_digest,
            &group_genesis_binding,
            sidecar_binding,
        )?,
    };
    state_store.with_write(|store| {
        store.cache_verified_mls_governance_proof(
            request.clone(),
            binding.clone(),
            &resolved.bundle,
            verified.target_checkpoint,
        )
    })?;
    Ok((resolved.bundle, binding))
}

pub(crate) fn verify_native_agent_history_key<S: GovernanceProofStateStore>(
    state_store: &S,
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
    evidence: &arkret_sdk::AuthenticatedSignerResolutionEvidence,
    dependencies: &[arkret_sdk::GovernanceDependency],
) -> Result<arkret_sdk::signatures::PublicKeyMaterial, arkret_sdk::WireError> {
    arkret_sdk::verify_native_agent_historical_event_key(
        event,
        digest_suite,
        evidence,
        dependencies,
        |request| verify_native_agent_external_trust(state_store, request),
    )
}

pub(crate) fn verify_native_agent_external_trust<S: GovernanceProofStateStore>(
    state_store: &S,
    request: arkret_sdk::NativeAgentHistoricalTrustRequest<'_>,
) -> Result<(), arkret_sdk::WireError> {
    match request {
        arkret_sdk::NativeAgentHistoricalTrustRequest::PcrSeal(seal) => {
            let checkpoint = state_store
                .with_read(|store| store.trusted_mls_governance_checkpoint(seal.realm_id.as_str()))
                .ok_or_else(|| {
                    arkret_sdk::WireError::Protocol(
                        "Native Agent PCR has no locally verified governance checkpoint".to_owned(),
                    )
                })?;
            checkpoint
                .accepted_seals
                .iter()
                .any(|accepted| accepted == seal)
                .then_some(())
                .ok_or_else(|| {
                    arkret_sdk::WireError::Protocol(
                        "Native Agent PCR Seal is not byte-exact in the verified checkpoint"
                            .to_owned(),
                    )
                })
        }
        arkret_sdk::NativeAgentHistoricalTrustRequest::LifecycleWitness(witness) => {
            let checkpoint = state_store
                .with_read(|store| {
                    store.trusted_mls_governance_checkpoint(witness.seal.realm_id.as_str())
                })
                .ok_or_else(|| {
                    arkret_sdk::WireError::Protocol(
                        "Native Agent lifecycle has no locally verified governance checkpoint"
                            .to_owned(),
                    )
                })?;
            let seal_is_accepted = checkpoint
                .accepted_seals
                .iter()
                .any(|accepted| accepted == &witness.seal);
            let event_is_accepted = checkpoint
                .accepted_events
                .iter()
                .any(|accepted| accepted == &witness.accepted_status_event);
            (seal_is_accepted && event_is_accepted)
                    .then_some(())
                    .ok_or_else(|| {
                        arkret_sdk::WireError::Protocol(
                            "Native Agent lifecycle witness is not byte-exact in the verified checkpoint"
                                .to_owned(),
                        )
                    })
        }
        arkret_sdk::NativeAgentHistoricalTrustRequest::Transparency(_) => {
            Err(arkret_sdk::WireError::Protocol(
                "Native Agent transparency has no independently pinned local witness policy"
                    .to_owned(),
            ))
        }
    }
}

pub(crate) async fn resolve_proof_signer_document(
    api: &crate::transport::TransportClient,
    did: &arkret_sdk::DidFullId,
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

pub(crate) async fn ensure_governance_checkpoint<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    realm_id: &str,
) -> Result<(), String> {
    if state_store
        .with_read(|store| store.trusted_mls_governance_checkpoint(realm_id))
        .is_some()
    {
        return Ok(());
    }
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| {
        format!("invalid Realm id for governance checkpoint bootstrap: {error}")
    })?;
    let mut leaves = state_store
        .with_read(|store| store.seal_view_for_realm(realm_id).frontier)
        .into_iter()
        .map(|seal| {
            arkret_sdk::SealId::new(seal)
                .map_err(|error| format!("invalid Realm Seal frontier id: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    leaves.sort();
    leaves.dedup();
    if leaves.is_empty() {
        return Err(
            "governance checkpoint bootstrap requires the complete synchronized Seal antichain"
                .to_owned(),
        );
    }
    let target_basis = arkret_sdk::SealBasis { leaves };
    let resolved = crate::mls::governance_acquisition::resolve_mls_governance_checkpoint(
        api,
        &realm,
        &target_basis,
    )
    .await?;
    let verified = arkret_sdk::verify_mls_governance_closure(
        &realm,
        &resolved.target_basis,
        &resolved.seals,
        &resolved.events,
        &resolved.dependencies,
        |event, digest_suite, evidence, dependencies| {
            verify_native_agent_history_key(
                &state_store,
                event,
                digest_suite,
                evidence,
                dependencies,
            )
        },
    )
    .map_err(|error| format!("verify initial MLS governance checkpoint: {error}"))?
    .checkpoint;
    state_store.with_write(|store| store.pin_mls_governance_checkpoint(realm_id, verified))
}

pub(crate) fn cached_verified_binding(
    state_store: &crate::state::LocalStateStore,
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    let entry = state_store
        .cached_mls_governance_proof_entry(request, chrono::Utc::now())?
        .ok_or_else(|| {
            "full-profile MLS governance binding requires a fresh, locally verified accepted-Seal proof; operation remains decryption_pending (state_mismatch)"
                .to_owned()
        })?;
    verify_request_binding(request, &entry.governance_binding)?;
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance proof has no Realm scope".to_owned())?;
    let pinned = state_store
        .trusted_mls_governance_checkpoint(realm_id.as_str())
        .ok_or_else(|| "MLS governance checkpoint is not pinned".to_owned())?;
    if pinned.basis != entry.proof_target_basis {
        return Err("cached MLS governance proof target is no longer the pinned basis".to_owned());
    }
    Ok(entry.governance_binding)
}

pub(crate) fn cached_verified_binding_for_transition(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    mls_group_id: &str,
    previous_epoch: u64,
    next_epoch: u64,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    state_store.cached_mls_governance_binding_for_transition(
        effective_scope,
        mls_group_id,
        previous_epoch,
        next_epoch,
        chrono::Utc::now(),
    )
}

/// Seeds a post-verification state for tests that exercise later MLS runtime
/// behavior. Verifier and acquisition tests must use real signed fixtures.
#[cfg(test)]
pub(crate) fn seed_test_governance_proof(
    state_store: &mut crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
) -> arkret_sdk::MlsGovernanceBindingPayload {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap();
    let effective_scope = match circle_id {
        Some(circle_id) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned()).unwrap(),
        },
        None => arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
    };
    let mls_group_id = arkret_sdk::Base64UrlString::new(mls_group_id.into()).unwrap();
    let anchor = arkret_sdk::SealId::new(
        "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let basis = arkret_sdk::SealBasis {
        leaves: vec![anchor.clone()],
    };
    let checkpoint = arkret_sdk::MlsGovernanceVerificationCheckpoint {
        realm_id: realm_id.clone(),
        basis: basis.clone(),
        live_digest_suite: arkret_sdk::DigestSuite::Sha256,
        accepted_seals: Vec::new(),
        accepted_events: Vec::new(),
        governance_dependencies: Vec::new(),
    };
    state_store.set_realm_seal_view(
        realm_id.as_str(),
        crate::state::LocalSealView {
            frontier: vec![anchor.to_string()],
            ..Default::default()
        },
    );
    let base_group_state_ref = if previous_epoch == 0 && next_epoch == 0 {
        None
    } else {
        let event_id =
            arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml")
                .unwrap();
        state_store
            .record_mls_group_state_ref_for_scope(
                &effective_scope,
                mls_group_id.as_str(),
                previous_epoch,
                event_id.clone(),
            )
            .unwrap();
        Some(event_id)
    };
    let request = arkret_sdk::MlsGovernanceProofRequestBody {
        profile: arkret_sdk::MlsGovernanceProofProfile::GroupSecurityFrontier,
        effective_scope,
        mls_group_id,
        local_mls_leaves: seed_test_security_frontier_leaves(),
        proof_base_basis: basis.clone(),
        proof_target_basis: basis.clone(),
        byte_limit: arkret_sdk::MLS_GOVERNANCE_PROOF_MAX_BYTES,
        frontier_purpose: arkret_sdk::MlsGovernanceFrontierPurpose::GroupBinding,
        base_group_state_ref,
        previous_epoch,
        next_epoch,
        binding_profile: arkret_sdk::MlsGovernanceBindingProfile::AkSecurityFrontierV1,
    };
    request.validate().unwrap();
    let root = arkret_sdk::Hash::new(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let genesis_binding = arkret_sdk::MlsGroupGenesisBinding {
        content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
        durability_policy: None,
    };
    let binding =
        binding_from_verified_frontier(&request, root.clone(), &genesis_binding, None).unwrap();
    let mut bundle = arkret_sdk::MlsGovernanceProofBundle {
        query_digest: request.query_digest().unwrap(),
        frontier_projection: arkret_sdk::MlsGovernanceFrontierProjection {
            frontier_registry_digest: arkret_sdk::Hash::new(
                arkret_sdk::MLS_SECURITY_FRONTIER_REGISTRY_DIGEST,
            )
            .unwrap(),
            branches: vec![arkret_sdk::MlsGovernanceFrontierBranchProjection {
                target_seal_ref: anchor.clone(),
                state_root: root.clone(),
                entries: Vec::new(),
                range_witnesses: Vec::new(),
            }],
        },
        proof_material: arkret_sdk::MlsGovernanceTypedProofMaterial {
            seal_descriptors: vec![arkret_sdk::MlsGovernanceSealDescriptor {
                seal_ref: anchor,
                seal_digest: root.clone(),
            }],
            seal_predecessor_edges: Vec::new(),
            event_ids: Vec::new(),
        },
        page_digest: root,
    };
    bundle.page_digest = bundle.recompute_page_digest().unwrap();
    state_store
        .seed_test_verified_mls_governance_cache(request, binding.clone(), bundle, checkpoint)
        .unwrap();
    binding
}

#[cfg(test)]
pub(crate) fn seed_test_security_frontier_leaves() -> Vec<arkret_sdk::MlsSecurityFrontierLeaf> {
    vec![arkret_sdk::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:webvh:z6mkfixturealice:alice.example",
        )
        .unwrap(),
        credential_ref: arkret_sdk::NonEmptyString::new(
            "did:webvh:z6mkfixturealice:alice.example#device-1",
        )
        .unwrap(),
    }]
}

fn binding_from_verified_frontier(
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    security_frontier_digest: arkret_sdk::Hash,
    group_genesis_binding: &arkret_sdk::MlsGroupGenesisBinding,
    sidecar_binding: Option<&arkret_sdk::SidecarMlsBinding>,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    let binding = match &request.effective_scope {
        arkret_wire::ScopeRef::Realm { realm_id } => {
            arkret_sdk::MlsGovernanceBindingPayload::realm(
                realm_id.clone(),
                request.mls_group_id.clone(),
                request.previous_epoch,
                request.next_epoch,
                security_frontier_digest,
                group_genesis_binding.content_scheme,
                group_genesis_binding.durability_policy,
                arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
                arkret_sdk::CORE_REDUCER_PROFILE,
            )
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_sdk::MlsGovernanceBindingPayload::circle(
            realm_id.clone(),
            circle_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            security_frontier_digest,
            group_genesis_binding.content_scheme,
            group_genesis_binding.durability_policy,
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        ),
        arkret_wire::ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } => arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            realm_id.clone(),
            sidecar_id.clone(),
            request.mls_group_id.clone(),
            request.previous_epoch,
            request.next_epoch,
            security_frontier_digest,
            sidecar_binding.cloned().ok_or_else(|| {
                "Sidecar MLS proof requires the accepted Sidecar binding".to_owned()
            })?,
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        ),
        _ => return Err("unsupported MLS governance effective scope".to_owned()),
    };
    binding.map_err(|error| format!("construct verified MLS governance binding: {error}"))
}

fn verify_request_binding(
    request: &arkret_sdk::MlsGovernanceProofRequestBody,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<(), String> {
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    let realm_id = request
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance proof has no Realm scope".to_owned())?;
    if binding.realm_id() != realm_id
        || binding.effective_scope() != &request.effective_scope
        || binding.mls_group_id() != request.mls_group_id.as_str()
        || binding.previous_epoch() != request.previous_epoch
        || binding.next_epoch() != request.next_epoch
        || binding.binding_profile() != arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1
        || binding.reducer_profile() != arkret_sdk::CORE_REDUCER_PROFILE
    {
        return Err("MLS governance proof binding differs from the exact request".to_owned());
    }
    Ok(())
}

pub(crate) fn singleton_security_frontier_leaf(
    principal_id: &str,
    device_id: &str,
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    Ok(vec![arkret_sdk::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        principal_id: crate::mls_api_helpers::principal_core_id(principal_id)
            .map_err(|error| format!("MLS leaf principal is invalid: {error}"))?,
        credential_ref: arkret_sdk::NonEmptyString::new(format!("{principal_id}#{device_id}"))
            .map_err(|error| format!("MLS leaf credential ref is invalid: {error}"))?,
    }])
}

pub(crate) fn current_security_frontier_leaves(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    let effective_scope = match circle_id {
        Some(circle_id) => arkret_sdk::ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| format!("invalid MLS Circle id: {error}"))?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id: realm },
    };
    current_security_frontier_leaves_for_scope(state_store, &effective_scope, authority, device_id)
}

pub(crate) fn current_security_frontier_leaves_for_scope(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    let snapshot = state_store
        .mls_snapshot_for_scope(effective_scope)
        .ok_or_else(|| "MLS security frontier requires a local group snapshot".to_owned())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        authority,
        device_id,
    )
    .map_err(|error| format!("load MLS snapshot secret for frontier: {error}"))?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|error| format!("restore MLS group for frontier: {error}"))?;
    group
        .security_frontier_leaves()
        .map_err(|error| format!("derive MLS security frontier leaves: {error}"))
}

pub(crate) fn security_frontier_with_added_claims(
    mut leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
    records: &[&arkret_sdk::KeyPackageClaimRecord],
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    let mut next_index = leaves
        .iter()
        .map(|leaf| leaf.leaf_index)
        .max()
        .map_or(0, |index| index.saturating_add(1));
    for record in records {
        let claim_method = arkret_sdk::DidUrl::new(record.device_signature.kid.as_str().to_owned())
            .map_err(|error| format!("claimed KeyPackage signer kid is invalid: {error}"))?;
        let signer_full_id = verification_method_did(&claim_method)
            .map_err(|error| format!("claimed KeyPackage signer is invalid: {error}"))?;
        if arkret_sdk::project_full_id_to_core_id(&signer_full_id)
            .map_err(|error| format!("project claimed KeyPackage signer: {error}"))?
            != record.principal_id
        {
            return Err("claimed KeyPackage signer does not project to principal_id".to_owned());
        }
        let key_package = arkret_sdk::base64url_decode(record.keypackage.as_bytes())
            .map_err(|error| format!("claimed KeyPackage decode failed: {error}"))?;
        let key_package_digest =
            arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&key_package))
                .map_err(|error| format!("claimed KeyPackage digest is invalid: {error}"))?;
        if key_package_digest != record.keypackage_digest {
            return Err("claimed KeyPackage bytes differ from keypackage_digest".to_owned());
        }
        let author_leaf = arkret_sdk::author_leaf_from_key_package_bytes(&key_package, next_index)
            .map_err(|error| format!("claimed KeyPackage validation failed: {error}"))?;
        let credential = match author_leaf.credential {
            arkret_sdk::AuthorLeafCredential::Basic { identity } => identity,
            arkret_sdk::AuthorLeafCredential::Other { .. } => {
                return Err("claimed KeyPackage credential is not Basic".to_owned());
            }
        };
        let credential = String::from_utf8(credential)
            .map_err(|_| "claimed KeyPackage credential is not UTF-8".to_owned())?;
        let credential_principal = credential
            .rsplit_once('#')
            .map(|(principal, _)| principal)
            .ok_or_else(|| "claimed KeyPackage credential has no endpoint fragment".to_owned())?;
        if credential_principal != record.principal_id.as_str() {
            return Err("claimed KeyPackage credential principal mismatch".to_owned());
        }
        leaves.push(arkret_sdk::MlsSecurityFrontierLeaf {
            leaf_index: next_index,
            principal_id: record.principal_id.clone(),
            credential_ref: arkret_sdk::NonEmptyString::new(credential)
                .map_err(|error| format!("claimed MLS credential ref is invalid: {error}"))?,
        });
        next_index = next_index.saturating_add(1);
    }
    leaves.sort_by_key(|leaf| leaf.leaf_index);
    Ok(leaves)
}

pub(crate) fn security_frontier_without_principals(
    mut leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
    removed: &[String],
) -> Vec<arkret_sdk::MlsSecurityFrontierLeaf> {
    let removed = removed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    leaves.retain(|leaf| !removed.contains(leaf.principal_id.as_str()));
    leaves
}
