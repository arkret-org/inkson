use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::identity::DidResolver;
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
    fn supports(&self, did: &arkret_sdk::Did) -> bool {
        self.documents.contains_key(did.as_str())
    }

    fn resolve_did(
        &self,
        did: &arkret_sdk::Did,
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
    let binding = match effective_scope {
        arkret_sdk::ScopeRef::Realm { .. } => {
            let state = state_store.load();
            let projection = state
                .realm_tree_projections
                .get(realm_id.as_str())
                .ok_or_else(|| {
                    "MLS governance proof requires the accepted Realm projection".to_owned()
                })?;
            crate::realm_tree::realm_projection_group_genesis_binding(projection).ok_or_else(
                || {
                    "MLS governance proof requires the exact accepted MLS Genesis binding"
                        .to_owned()
                },
            )?
        }
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => {
            let scheme = state_store
                .circle_content_scheme(realm_id.as_str(), circle_id.as_str())
                .ok_or_else(|| {
                    "MLS governance proof requires the accepted Circle content scheme".to_owned()
                })?;
            let content_scheme = match scheme.as_str() {
                "mls_rfc9420" => arkret_wire::ContentScheme::MlsRfc9420,
                "mls_exporter_aead_v1" => arkret_wire::ContentScheme::MlsExporterAeadV1,
                value => return Err(format!("unregistered MLS content scheme {value}")),
            };
            arkret_sdk::MlsGroupGenesisBinding {
                content_scheme,
                durability_policy: state_store
                    .circle_durability_policy(realm_id.as_str(), circle_id.as_str()),
            }
        }
        _ => return Err("unsupported MLS governance effective scope".to_owned()),
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
    _digest_suite: arkret_sdk::DigestSuite,
    evidence: &arkret_sdk::AuthenticatedSignerResolutionEvidence,
    dependencies: &[arkret_sdk::GovernanceDependency],
) -> Result<arkret_sdk::signatures::PublicKeyMaterial, arkret_sdk::WireError> {
    arkret_sdk::verify_native_agent_historical_event_key(event, evidence, dependencies, |request| {
        verify_native_agent_external_trust(state_store, request)
    })
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

pub(crate) async fn ensure_governance_checkpoint<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    realm_id: &str,
) -> Result<(), String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance checkpoint client: {error}"))?;
    ensure_governance_checkpoint_with_http(&http, state_store, realm_id).await
}

pub(crate) async fn ensure_governance_checkpoint_with_http<S: GovernanceProofStateStore>(
    http: &arkret_sdk::http_client::Client,
    state_store: S,
    realm_id: &str,
) -> Result<(), String> {
    if state_store
        .with_read(|store| store.trusted_mls_governance_checkpoint(realm_id))
        .is_some()
    {
        return Ok(());
    }
    let verified =
        verify_governance_checkpoint_candidate_with_http(http, &state_store, realm_id).await?;
    state_store.with_write(|store| store.pin_mls_governance_checkpoint(realm_id, verified))
}

pub(crate) async fn verify_governance_checkpoint_candidate<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: &S,
    realm_id: &str,
) -> Result<arkret_sdk::MlsGovernanceVerificationCheckpoint, String> {
    let http = api
        .sdk_http_client()
        .map_err(|error| format!("build MLS governance checkpoint client: {error}"))?;
    verify_governance_checkpoint_candidate_with_http(&http, state_store, realm_id).await
}

async fn verify_governance_checkpoint_candidate_with_http<S: GovernanceProofStateStore>(
    http: &arkret_sdk::http_client::Client,
    state_store: &S,
    realm_id: &str,
) -> Result<arkret_sdk::MlsGovernanceVerificationCheckpoint, String> {
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
    let resolved = crate::mls::governance_acquisition::resolve_mls_governance_checkpoint_with_http(
        http,
        &realm,
        &target_basis,
    )
    .await?;
    let checkpoint = arkret_sdk::verify_mls_governance_closure(
        &realm,
        &resolved.target_basis,
        &resolved.seals,
        &resolved.events,
        &resolved.dependencies,
        |event, digest_suite, evidence, dependencies| {
            verify_native_agent_history_key(
                state_store,
                event,
                digest_suite,
                evidence,
                dependencies,
            )
        },
    )
    .map_err(|error| format!("verify initial MLS governance checkpoint: {error}"))?
    .checkpoint;
    Ok(checkpoint)
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

/// Materialize the exact accepted MLS epoch CAS head from the pinned,
/// locally verified governance checkpoint. A producer must bind a Commit's
/// `head_eq` predicate to this whole registered value; the scalar epoch is
/// only one member of that value and is not a Cell head.
pub(crate) fn cached_verified_mls_epoch_head(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    mls_group_id: &str,
) -> Result<serde_json::Value, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS epoch Cell requires a Realm-backed scope".to_owned())?;
    let checkpoint = state_store
        .trusted_mls_governance_checkpoint(realm_id.as_str())
        .ok_or_else(|| "MLS governance checkpoint is not pinned".to_owned())?;
    let registry = arkret_sdk::lattice_registry::try_build_sdk_cell_registry()
        .map_err(|error| format!("MLS Cell registry construction failed: {error}"))?;
    let cell = arkret_sdk::mls_cells::mls_epoch_cell_id(effective_scope, mls_group_id)
        .map_err(|error| error.to_string())?;
    let authority_audits =
        arkret_schema::CapabilityAuthorityAuditIndex::from_events(&checkpoint.accepted_events);
    arkret_state::mls_governance_proof::materialize_registered_cell_value_from_verified_checkpoint(
        &checkpoint,
        &cell,
        &registry,
        |event, digest_suite| {
            arkret_schema::project_registered_cell_writes_with_authority_resolver(
                event,
                digest_suite,
                &|grant_id| authority_audits.resolve(grant_id),
            )
            .map_err(|error| error.to_string())
        },
    )
    .map_err(|error| error.to_string())
}

#[derive(Clone, Debug)]
pub(crate) struct MlsLeafAuthorityHint {
    pub(crate) endpoint: arkret_sdk::MlsEndpointIdentity,
    pub(crate) device_authorize_event_id: Option<arkret_sdk::EventId>,
}

pub(crate) fn leaf_authority_hint_from_claim(
    claim: &arkret_sdk::KeyPackageClaimRecord,
) -> Result<MlsLeafAuthorityHint, String> {
    claim
        .validate_shape()
        .map_err(|error| format!("invalid claimed MLS leaf authority: {error}"))?;
    let endpoint = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|error| format!("invalid claimed MLS endpoint: {error}"))?
        .endpoint;
    Ok(MlsLeafAuthorityHint {
        endpoint,
        device_authorize_event_id: claim.device_authorize_event_id.clone(),
    })
}

/// Recover the complete target only from the checked peer claim receipt,
/// never from the inviting client's selected Station.
pub(crate) fn claimed_actor_id(
    claim: &arkret_sdk::KeyPackageClaimRecord,
    receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::ActorId, String> {
    arkret_sdk::validate_target_claim_evidence(claim, receipt)
        .map_err(|error| format!("invalid target claim evidence: {error}"))?;
    if claim.pairwise_verification_method.is_some() {
        Ok(arkret_sdk::ActorId::service(claim.principal_id.clone()))
    } else if claim.agent_id.is_some() {
        Ok(arkret_sdk::ActorId::hosted_principal(
            claim.principal_id.clone(),
            receipt.destination_id.clone(),
        ))
    } else {
        Ok(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            claim.principal_id.clone(),
            receipt.destination_id.clone(),
        )))
    }
}

pub(crate) fn leaf_authority_hints_from_welcome(
    welcome: &arkret_sdk::MlsWelcomePayload,
) -> Result<Vec<MlsLeafAuthorityHint>, String> {
    let recipient = match (&welcome.recipient_principal_id, &welcome.recipient) {
        (
            Some(principal_id),
            arkret_sdk::MlsWelcomeRecipient::Device {
                recipient_device_id,
            },
        ) => {
            let event_id = welcome
                .claim_ref
                .trust_binding
                .device_authorize_event_id()
                .ok_or_else(|| {
                    "ordinary MLS Welcome recipient omits device authorization Event".to_owned()
                })?;
            MlsLeafAuthorityHint {
                endpoint: arkret_sdk::MlsEndpointIdentity::human_device(
                    principal_id.clone(),
                    recipient_device_id.clone(),
                ),
                device_authorize_event_id: Some(
                    arkret_sdk::EventId::new(event_id.to_owned())
                        .map_err(|error| format!("invalid recipient authority Event: {error}"))?,
                ),
            }
        }
        (
            Some(principal_id),
            arkret_sdk::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
        ) if principal_id == recipient_agent_id => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
                recipient_agent_id.clone(),
                recipient_agent_verification_method.clone(),
                agent_key_authorize_event_id.clone(),
            )
            .map_err(|error| format!("invalid recipient Agent authority: {error}"))?,
            device_authorize_event_id: None,
        },
        (
            None,
            arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            },
        ) => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
                recipient_pairwise_actor_id.clone(),
                recipient_pairwise_verification_method.clone(),
            )
            .map_err(|error| format!("invalid recipient pairwise authority: {error}"))?,
            device_authorize_event_id: None,
        },
        _ => return Err("MLS Welcome recipient authority shape is inconsistent".to_owned()),
    };

    let requester = match &welcome.claim_envelope.trust_binding {
        arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
            requester_device_id,
            requester_device_authorize_event_id,
        } => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::human_device(
                welcome
                    .claim_envelope
                    .requester_actor_id
                    .signing_principal_id()
                    .clone(),
                requester_device_id.clone(),
            ),
            device_authorize_event_id: Some(requester_device_authorize_event_id.clone()),
        },
        arkret_sdk::MlsRequesterTrustBinding::RequesterNativeAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
                requester_agent_id.clone(),
                requester_agent_verification_method.clone(),
                requester_agent_key_authorize_event_id.clone(),
            )
            .map_err(|error| format!("invalid requester Agent authority: {error}"))?,
            device_authorize_event_id: None,
        },
        arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
            requester_pairwise_verification_method,
        } => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
                welcome
                    .claim_envelope
                    .requester_actor_id
                    .signing_principal_id()
                    .clone(),
                requester_pairwise_verification_method.clone(),
            )
            .map_err(|error| format!("invalid requester pairwise authority: {error}"))?,
            device_authorize_event_id: None,
        },
    };
    Ok(vec![recipient, requester])
}

pub(crate) fn install_cached_transition_leaf_bindings(
    state_store: &crate::state::LocalStateStore,
    group: &mut arkret_sdk::ArkretMlsGroup,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<(), String> {
    install_cached_transition_leaf_bindings_with_hints(state_store, group, binding, &[])
}

pub(crate) fn install_cached_transition_leaf_bindings_with_hints(
    state_store: &crate::state::LocalStateStore,
    group: &mut arkret_sdk::ArkretMlsGroup,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
    authority_hints: &[MlsLeafAuthorityHint],
) -> Result<(), String> {
    let state = state_store.load();
    let mut matches = state.mls_governance_proofs.values().filter(|entry| {
        &entry.governance_binding == binding
            && entry.request.effective_scope == *binding.effective_scope()
            && entry.request.mls_group_id.as_str() == group.group_id()
            && entry.request.next_epoch == group.epoch()
    });
    let entry = matches
        .next()
        .ok_or_else(|| "accepted MLS transition has no verified T3 leaf set".to_owned())?;
    if matches.next().is_some() {
        return Err("accepted MLS transition has multiple verified T3 leaf sets".to_owned());
    }
    let realm_id = binding
        .effective_scope()
        .realm_id_opt()
        .ok_or_else(|| "accepted MLS transition has no Realm scope".to_owned())?;
    let checkpoint = state
        .mls_governance_checkpoints
        .get(realm_id.as_str())
        .ok_or_else(|| "accepted MLS transition has no pinned T3 checkpoint".to_owned())?;
    if checkpoint.basis != entry.proof_target_basis {
        return Err("accepted MLS transition leaf set is not pinned at T3".to_owned());
    }

    let author_leaves = group
        .active_author_leaves()
        .into_iter()
        .map(|leaf| (leaf.leaf_index, leaf))
        .collect::<BTreeMap<_, _>>();
    if author_leaves.len() != entry.request.local_mls_leaves.len() {
        return Err("verified T3 leaf set does not cover the post-transition MLS tree".to_owned());
    }
    let retained_bindings = group
        .retained_verified_leaf_bindings()
        .map_err(|error| format!("read retained MLS leaf bindings: {error}"))?
        .into_iter()
        .map(|binding| (binding.leaf_index, binding))
        .collect::<BTreeMap<_, _>>();
    let mut installed = Vec::with_capacity(author_leaves.len());
    for frontier_leaf in &entry.request.local_mls_leaves {
        let author_leaf = author_leaves
            .get(&frontier_leaf.leaf_index)
            .ok_or_else(|| "verified T3 leaf set names an empty MLS leaf".to_owned())?;
        let arkret_sdk::AuthorLeafCredential::Basic { identity } = &author_leaf.credential else {
            return Err("accepted Arkret MLS leaf does not use BasicCredential".to_owned());
        };
        if identity.as_slice() != frontier_leaf.credential_ref.as_bytes() {
            return Err("verified T3 credential differs from the post-transition leaf".to_owned());
        }
        let signature_key: [u8; 32] = author_leaf
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| "accepted MLS leaf signature key is not Ed25519".to_owned())?;
        let multibase = arkret_sdk::ed25519_pubkey_to_did_key_multibase(&signature_key);
        let signature_key_b64 =
            arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(signature_key))
                .map_err(|error| format!("invalid accepted MLS leaf key: {error}"))?;
        let credential = frontier_leaf.credential_ref.as_str();

        if let Some(retained) = retained_bindings.get(&frontier_leaf.leaf_index) {
            if retained.actor_id != frontier_leaf.actor_id
                || retained.credential_ref != frontier_leaf.credential_ref
                || retained.signature_key != signature_key_b64
            {
                return Err("retained MLS authority differs from the verified T3 leaf".to_owned());
            }
            installed.push(retained.clone());
            continue;
        }

        let (endpoint, device_authorize_event_id) = if let Ok(device_id) =
            arkret_sdk::DeviceId::new(credential.to_owned())
        {
            let endpoint = arkret_sdk::MlsEndpointIdentity::human_device(
                frontier_leaf.actor_id.signing_principal_id().clone(),
                device_id.clone(),
            );
            let mut hints = authority_hints
                .iter()
                .filter(|hint| hint.endpoint == endpoint);
            let hinted = hints.next();
            if hints.next().is_some() {
                return Err("ordinary MLS leaf has duplicate authority hints at T3".to_owned());
            }
            let authority = if let Some(hint) = hinted {
                hint.device_authorize_event_id.clone().ok_or_else(|| {
                    "ordinary MLS leaf authority hint omits device authorization Event".to_owned()
                })?
            } else {
                let cached_key = match crate::identity::device_directory::cached_device_signing_key(
                    &frontier_leaf.actor_id.to_string(),
                    device_id.as_str(),
                ) {
                    crate::identity::device_directory::CacheLookup::Hit(key) => key,
                    crate::identity::device_directory::CacheLookup::NegativeHit
                    | crate::identity::device_directory::CacheLookup::Miss => {
                        return Err(
                            "ordinary MLS leaf has no verified PCR device authority at T3"
                                .to_owned(),
                        );
                    }
                };
                if cached_key
                    .ed25519_bytes()
                    .map_err(|error| format!("invalid cached device authority key: {error}"))?
                    != signature_key
                {
                    return Err(
                        "ordinary MLS leaf key differs from its verified PCR device authority"
                            .to_owned(),
                    );
                }
                crate::identity::device_directory::cached_device_authorize_event_id(
                    &frontier_leaf.actor_id.to_string(),
                    device_id.as_str(),
                )
                .ok_or_else(|| {
                    "ordinary MLS leaf PCR authority omits device authorization Event".to_owned()
                })?
            };
            (endpoint, Some(authority))
        } else if credential.starts_with("ak:did_core:key:") {
            let expected_actor = format!("ak:did_core:key:{multibase}");
            if credential != expected_actor
                || frontier_leaf.actor_id.signing_principal_id().as_str() != credential
            {
                return Err(
                    "minimal-metadata MLS credential does not name its exact leaf key".to_owned(),
                );
            }
            let method = arkret_sdk::DidUrl::new(format!("did:key:{multibase}#{multibase}"))
                .map_err(|error| format!("invalid pairwise MLS method: {error}"))?;
            (
                arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
                    frontier_leaf.actor_id.signing_principal_id().clone(),
                    method,
                )
                .map_err(|error| format!("invalid pairwise MLS endpoint: {error}"))?,
                None,
            )
        } else {
            if frontier_leaf.actor_id.signing_principal_id().as_str() != credential {
                return Err("Native Agent MLS credential differs from its principal".to_owned());
            }
            let mut hints = authority_hints.iter().filter(|hint| {
                matches!(
                    &hint.endpoint,
                    arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime { agent_id, .. }
                        if agent_id == frontier_leaf.actor_id.signing_principal_id()
                )
            });
            let hint = hints.next().ok_or_else(|| {
                "Native Agent MLS leaf has no verified authority hint at T3".to_owned()
            })?;
            if hints.next().is_some() {
                return Err("Native Agent MLS leaf has duplicate authority hints at T3".to_owned());
            }
            (hint.endpoint.clone(), None)
        };
        installed.push(arkret_sdk::MlsVerifiedLeafBinding {
            leaf_index: frontier_leaf.leaf_index,
            actor_id: frontier_leaf.actor_id.clone(),
            endpoint,
            credential_ref: frontier_leaf.credential_ref.clone(),
            signature_key: signature_key_b64,
            device_authorize_event_id,
        });
    }
    group
        .install_verified_leaf_bindings(installed)
        .map_err(|error| format!("install accepted T3 MLS leaf bindings: {error}"))
}

pub(crate) fn reconstruct_transition_security_frontier(
    checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
    group: &arkret_sdk::ArkretMlsGroup,
    binding: &arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    let realm_id = binding
        .effective_scope()
        .realm_id_opt()
        .ok_or_else(|| "MLS transition has no Realm scope".to_owned())?;
    if &checkpoint.realm_id != realm_id {
        return Err("MLS transition checkpoint belongs to another Realm".to_owned());
    }

    let mut genesis_matches = checkpoint.accepted_events.iter().filter(|event| {
        event.kind == arkret_sdk::EventKind::MlsGenesis
            && serde_json::from_value::<arkret_sdk::MlsGenesisPayload>(
                serde_json::to_value(&event.payload).unwrap_or_default(),
            )
            .is_ok_and(|payload| payload.mls_group_id.as_str() == group.group_id())
    });
    let genesis = genesis_matches
        .next()
        .ok_or_else(|| "MLS transition replay has no accepted Genesis".to_owned())?;
    if genesis_matches.next().is_some() {
        return Err("MLS transition replay has multiple accepted Genesis Events".to_owned());
    }
    let mut principals = BTreeMap::from([(0_u32, genesis.actor_id.clone())]);

    let mut commits = checkpoint
        .accepted_events
        .iter()
        .filter_map(|event| {
            if event.kind != arkret_sdk::EventKind::MlsCommit {
                return None;
            }
            let payload = serde_json::from_value::<arkret_sdk::MlsCommitPayload>(
                serde_json::to_value(&event.payload).ok()?,
            )
            .ok()?;
            (payload.mls_group_id() == group.group_id() && payload.next_epoch() <= group.epoch())
                .then_some((payload.next_epoch(), payload))
        })
        .collect::<Vec<_>>();
    commits.sort_by_key(|(epoch, _)| *epoch);
    if commits.len() != usize::try_from(group.epoch()).unwrap_or(usize::MAX)
        || commits
            .iter()
            .enumerate()
            .any(|(index, (epoch, _))| *epoch != index as u64 + 1)
    {
        return Err(
            "MLS transition replay does not contain one winning Commit per epoch".to_owned(),
        );
    }
    for (_, commit) in commits {
        for proposal_ref in commit.proposal_refs() {
            let mut proposals = checkpoint
                .accepted_events
                .iter()
                .filter(|event| &event.event_id == proposal_ref);
            let event = proposals.next().ok_or_else(|| {
                "winning MLS Commit references an unavailable accepted Proposal".to_owned()
            })?;
            if proposals.next().is_some() || event.kind != arkret_sdk::EventKind::MlsProposal {
                return Err(
                    "winning MLS Commit proposal reference is ambiguous or has the wrong kind"
                        .to_owned(),
                );
            }
            let proposal = serde_json::from_value::<arkret_sdk::MlsProposalPayload>(
                serde_json::to_value(&event.payload)
                    .map_err(|error| format!("encode accepted MLS Proposal: {error}"))?,
            )
            .map_err(|error| format!("decode accepted MLS Proposal: {error}"))?;
            if proposal.mls_group_id.as_str() != group.group_id()
                || proposal.base_epoch != commit.base_epoch()
            {
                return Err(
                    "winning MLS Commit references a Proposal from another group or epoch"
                        .to_owned(),
                );
            }
            let target = proposal.target_actor_id.ok_or_else(|| {
                "accepted MLS membership Proposal omits target_actor_id".to_owned()
            })?;
            match proposal.proposal_type {
                arkret_sdk::MlsProposalType::Add => {
                    let index = (0..=u32::MAX)
                        .find(|index| !principals.contains_key(index))
                        .ok_or_else(|| "MLS transition replay has no free leaf index".to_owned())?;
                    principals.insert(index, target);
                }
                arkret_sdk::MlsProposalType::Remove => {
                    let removed = principals
                        .iter()
                        .filter_map(|(index, principal)| (principal == &target).then_some(*index))
                        .collect::<Vec<_>>();
                    if removed.is_empty() {
                        return Err(
                            "accepted MLS Remove targets no replayed principal leaf".to_owned()
                        );
                    }
                    for index in removed {
                        principals.remove(&index);
                    }
                }
                arkret_sdk::MlsProposalType::Update => {
                    if !principals.values().any(|principal| principal == &target) {
                        return Err(
                            "accepted MLS Update targets no replayed principal leaf".to_owned()
                        );
                    }
                }
                _ => {
                    return Err(
                        "winning MLS Commit references a non-membership Proposal Event".to_owned(),
                    );
                }
            }
        }
    }

    let mut leaves = Vec::new();
    for leaf in group.active_author_leaves() {
        let principal_id = principals
            .remove(&leaf.leaf_index)
            .ok_or_else(|| "post-transition MLS tree has an unattributed leaf".to_owned())?;
        let arkret_sdk::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            return Err("post-transition Arkret MLS leaf is not BasicCredential".to_owned());
        };
        let credential_ref = arkret_sdk::NonEmptyString::new(
            String::from_utf8(identity)
                .map_err(|_| "post-transition MLS credential is not UTF-8".to_owned())?,
        )
        .map_err(|error| format!("invalid post-transition MLS credential: {error}"))?;
        leaves.push(arkret_sdk::MlsSecurityFrontierLeaf {
            leaf_index: leaf.leaf_index,
            actor_id: principal_id,
            credential_ref,
        });
    }
    if !principals.is_empty() {
        return Err("accepted MLS transition replay leaves phantom members".to_owned());
    }
    leaves.sort_by_key(|leaf| leaf.leaf_index);
    Ok(leaves)
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
                cells: Vec::new(),
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
        actor_id: crate::mls_api_helpers::local_account_actor_id(
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
    actor_id: &arkret_sdk::ActorId,
    device_id: &str,
) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
    Ok(vec![arkret_sdk::MlsSecurityFrontierLeaf {
        leaf_index: 0,
        actor_id: actor_id.clone(),
        credential_ref: arkret_sdk::NonEmptyString::new(device_id.to_owned())
            .map_err(|error| format!("MLS leaf credential ref is invalid: {error}"))?,
    }])
}

pub(crate) fn current_security_frontier_leaves(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::AccountId,
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
    authority: &arkret_sdk::AccountId,
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

pub(crate) fn preview_security_frontier_with_added_keypackages(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    records: &[arkret_sdk::MlsKeyPackageRecord],
    actors: &[arkret_sdk::ActorId],
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
    .map_err(|error| format!("load MLS snapshot secret for Add preview: {error}"))?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|error| format!("restore MLS group for Add preview: {error}"))?;
    group
        .preview_add_members_security_frontier(records, actors)
        .map_err(|error| format!("stage exact MLS Add frontier: {error}"))
}

pub(crate) fn security_frontier_without_actors(
    mut leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
    removed: &[arkret_sdk::ActorId],
) -> Vec<arkret_sdk::MlsSecurityFrontierLeaf> {
    let removed = removed.iter().collect::<BTreeSet<_>>();
    leaves.retain(|leaf| !removed.contains(&leaf.actor_id));
    leaves
}

#[cfg(test)]
mod actor_frontier_tests {
    use super::*;

    #[test]
    fn removing_one_station_actor_preserves_other_account_with_same_principal() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actors = ["alpha.example", "beta.example"].map(|station| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{station}")).unwrap(),
            ))
        });
        let leaves = actors
            .iter()
            .enumerate()
            .map(|(index, actor)| arkret_sdk::MlsSecurityFrontierLeaf {
                leaf_index: index as u32,
                actor_id: actor.clone(),
                credential_ref: arkret_sdk::NonEmptyString::new(format!("device-{index}")).unwrap(),
            })
            .collect();
        let retained = security_frontier_without_actors(leaves, &[actors[0].clone()]);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].actor_id, actors[1]);
    }
}
