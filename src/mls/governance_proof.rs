use std::collections::{BTreeMap, BTreeSet};

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

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait GovernanceProofStateStorePlatform: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> GovernanceProofStateStorePlatform for T {}
#[cfg(target_arch = "wasm32")]
pub(crate) trait GovernanceProofStateStorePlatform {}
#[cfg(target_arch = "wasm32")]
impl<T> GovernanceProofStateStorePlatform for T {}

pub(crate) trait GovernanceProofStateStore:
    Clone + GovernanceProofStateStorePlatform + 'static
{
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R;
    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R;
}

impl GovernanceProofStateStore for crate::runtime::input::StateStoreHandle {
    fn with_read<R>(&self, read: impl FnOnce(&crate::state::LocalStateStore) -> R) -> R {
        self.read(read)
    }

    fn with_write<R>(&self, write: impl FnOnce(&mut crate::state::LocalStateStore) -> R) -> R {
        self.write(write)
    }
}

pub(crate) fn frontier_request(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
    local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
) -> Result<arkret_sdk::MlsGovernanceFrontierRequestBody, String> {
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
    frontier_request_for_scope(
        state_store,
        effective_scope,
        mls_group_id,
        previous_epoch,
        next_epoch,
        local_mls_leaves,
    )
}

pub(crate) fn frontier_request_for_scope(
    state_store: &crate::state::LocalStateStore,
    effective_scope: arkret_sdk::ScopeRef,
    mls_group_id: impl Into<String>,
    previous_epoch: u64,
    next_epoch: u64,
    local_mls_leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
) -> Result<arkret_sdk::MlsGovernanceFrontierRequestBody, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .cloned()
        .ok_or_else(|| "MLS governance proof rejects RealmGenesis scope".to_owned())?;
    let mls_group_id = arkret_sdk::Base64UrlString::new(mls_group_id.into())
        .map_err(|error| format!("invalid MLS group id: {error}"))?;
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
    let seal_basis = arkret_sdk::SealBasis {
        leaves: target_leaves,
    };
    seal_basis
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
    let genesis = previous_epoch == 0 && next_epoch == 0;
    let accepted_genesis_exists = genesis
        && state_store
            .mls_group_state_ref_for_scope(&effective_scope, mls_group_id.as_str(), 0)
            .is_ok();
    let proposed_group_genesis_binding = if genesis && !accepted_genesis_exists {
        Some(proposed_group_genesis_binding(
            state_store,
            &effective_scope,
        )?)
    } else {
        None
    };
    let request = arkret_sdk::MlsGovernanceFrontierRequestBody {
        effective_scope,
        mls_group_id,
        local_mls_leaves,
        seal_basis,
        base_group_state_ref,
        proposed_group_genesis_binding,
        previous_epoch,
        next_epoch,
    };
    request
        .validate()
        .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
    Ok(request)
}

fn proposed_group_genesis_binding(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<arkret_sdk::ProposedMlsGroupGenesisBinding, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS governance scope has no Realm".to_owned())?;
    let (content_scheme, durability_policy) = match effective_scope {
        arkret_sdk::ScopeRef::Realm { .. } => {
            let state = state_store.load();
            let projection = state
                .realm_tree_projections
                .get(realm_id.as_str())
                .ok_or_else(|| {
                    "pre-Genesis MLS proposal requires the accepted Realm projection".to_owned()
                })?;
            if let Some(proposal) = direct_conversation_genesis_proposal(projection) {
                return Ok(proposal);
            }
            let scheme = crate::realm_tree::realm_projection_content_scheme(projection)
                .ok_or_else(|| {
                    "pre-Genesis MLS proposal requires an explicit content scheme".to_owned()
                })?;
            let durability = projection
                .get("durability_policy")
                .or_else(|| projection.pointer("/summary/durability_policy"))
                .filter(|value| !value.is_null())
                .map(|value| {
                    serde_json::from_value::<arkret_wire::DurabilityPolicy>(value.clone())
                        .map_err(|error| format!("invalid proposed durability policy: {error}"))
                })
                .transpose()?;
            (scheme, durability)
        }
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => (
            state_store
                .circle_content_scheme(realm_id.as_str(), circle_id.as_str())
                .ok_or_else(|| {
                    "pre-Genesis Circle proposal requires the accepted Circle content scheme"
                        .to_owned()
                })?,
            state_store.circle_durability_policy(realm_id.as_str(), circle_id.as_str()),
        ),
        _ => return Err("unsupported MLS governance effective scope".to_owned()),
    };
    let content_scheme = match content_scheme.as_str() {
        "mls_rfc9420" => arkret_wire::ContentScheme::MlsRfc9420,
        "mls_exporter_aead_v1" => arkret_wire::ContentScheme::MlsExporterAeadV1,
        value => return Err(format!("unregistered proposed MLS content scheme {value}")),
    };
    let proposal = arkret_sdk::ProposedMlsGroupGenesisBinding {
        content_scheme,
        durability_policy,
    };
    proposal
        .validate()
        .map_err(|error| format!("invalid proposed MLS Genesis binding: {error}"))?;
    Ok(proposal)
}

/// The current Direct Conversation profile fixes the exporter scheme. This
/// is authoring input to the 0->0 proof query, never an accepted binding or a
/// send-readiness shortcut. The application selects no organization recovery
/// for a private conversation; the accepted MLS Genesis locks that choice.
fn direct_conversation_genesis_proposal(
    projection: &serde_json::Value,
) -> Option<arkret_sdk::ProposedMlsGroupGenesisBinding> {
    crate::realm_tree::projected_state_event_values(projection)
        .filter(|event| event.get("kind").and_then(serde_json::Value::as_str)
            == Some(arkret_sdk::EventKind::RealmCreate.as_str()))
        .find_map(|event| {
            let payload = serde_json::from_value::<arkret_sdk::RealmCreatePayload>(
                event.get("payload")?.clone(),
            ).ok()?;
            arkret_models_collaboration::objects::direct_conversation::DirectConversationRealmRole::validate(&payload.object).ok()?;
            Some(arkret_sdk::ProposedMlsGroupGenesisBinding {
                content_scheme: arkret_wire::ContentScheme::MlsExporterAeadV1,
                durability_policy: Some(arkret_wire::DurabilityPolicy::None),
            })
        })
}

pub(crate) async fn fetch_and_cache_frontier<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state_store: S,
    request: &arkret_sdk::MlsGovernanceFrontierRequestBody,
    leaves: &[arkret_sdk::MlsSecurityFrontierLeaf],
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    if request.local_mls_leaves != leaves {
        return Err("MLS authoring leaf intent changed".to_owned());
    }
    let authority = state_store
        .with_read(|store| store.active_authority())
        .ok_or_else(|| "MLS authoring requires an active account".to_owned())?;
    let epoch = crate::identity::device_directory::cache_epoch();
    let http = api.sdk_http_client().map_err(|error| error.to_string())?;
    let outcome = http
        .mls_governance_frontier(request)
        .await
        .map_err(|error| error.to_string())?;
    let binding = outcome.governance_binding.clone();
    state_store.with_write(|store| {
        let realm = request
            .effective_scope
            .realm_id_opt()
            .ok_or_else(|| "MLS authoring scope has no Realm".to_owned())?;
        if store.active_authority().as_ref() != Some(&authority)
            || epoch != crate::identity::device_directory::cache_epoch()
            || store.seal_view_for_realm(realm.as_str()).frontier
                != request
                    .seal_basis
                    .leaves
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
        {
            return Err(
                "MLS authoring response arrived after account or frontier changed".to_owned(),
            );
        }
        store.cache_mls_governance_result(request.clone(), outcome)
    })?;
    Ok(binding)
}

pub(crate) async fn refresh_realm_frontier_with_http<S: GovernanceProofStateStore>(
    http: &arkret_sdk::http_client::Client,
    state_store: S,
    realm_id: &str,
) -> Result<arkret_sdk::DigestSuite, String> {
    let authority = state_store
        .with_read(|store| store.active_authority())
        .ok_or_else(|| "Realm frontier requires an active account".to_owned())?;
    let epoch = crate::identity::device_directory::cache_epoch();
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned()).map_err(|error| error.to_string())?;
    // Realm admission can precede the first asynchronous control Seal.
    // Retry only that registered transient condition, never an auth failure
    // or a malformed frontier. Keep the original session pinned while waiting.
    let mut attempt = 0;
    let result = loop {
        if state_store
            .with_read(|store| store.active_authority())
            .as_ref()
            != Some(&authority)
            || epoch != crate::identity::device_directory::cache_epoch()
        {
            return Err("Realm frontier wait cancelled after its session changed".to_owned());
        }
        match http.seals_frontier(realm.clone()).await {
            Ok(result) => break result.frontier,
            Err(error) => {
                let Some(delay) = frontier_retry_delay(&error, attempt) else {
                    return Err(error.to_string());
                };
                attempt += 1;
                crate::runtime_helpers::sleep_for(delay).await;
            }
        }
    };
    if result.realm_id != realm {
        return Err("Station frontier returned another Realm".to_owned());
    }
    let suite = result.live_digest_suite;
    state_store.with_write(|store| {
        if store.active_authority().as_ref() != Some(&authority)
            || epoch != crate::identity::device_directory::cache_epoch()
        {
            return Err("Realm frontier arrived after its session changed".to_owned());
        }
        store.cache_realm_governance_frontier(result)
    })?;
    Ok(suite)
}

fn frontier_retry_delay(
    error: &arkret_sdk::http_client::Error,
    attempt: u32,
) -> Option<std::time::Duration> {
    (error.error_code().is_some_and(|code| {
        code.as_str() == arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE
    }) && attempt < 8)
        .then(|| std::time::Duration::from_millis((250_u64 << attempt).min(2_000)))
}

#[cfg(test)]
mod frontier_wait_tests {
    use super::*;

    #[test]
    fn frontier_wait_is_bounded_and_does_not_retry_other_failures() {
        let pending = arkret_sdk::http_client::Error::Api {
            status: 503,
            error: Box::new(arkret_sdk::Problem::from_code(
                "frontier_unavailable",
                "Realm has no accepted Seal",
            )),
        };
        let delays = (0..8)
            .map(|attempt| frontier_retry_delay(&pending, attempt).unwrap().as_millis())
            .collect::<Vec<_>>();
        assert_eq!(delays, [250, 500, 1000, 2000, 2000, 2000, 2000, 2000]);
        assert!(frontier_retry_delay(&pending, 8).is_none());
        for code in ["unauthorized", "not_found", "param_invalid"] {
            let error = arkret_sdk::http_client::Error::Api {
                status: 403,
                error: Box::new(arkret_sdk::Problem::from_code(code, "terminal")),
            };
            assert!(frontier_retry_delay(&error, 0).is_none());
        }
    }
}

pub(crate) fn cached_frontier_binding(
    store: &crate::state::LocalStateStore,
    request: &arkret_sdk::MlsGovernanceFrontierRequestBody,
) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
    store
        .cached_mls_governance_result_entry(request, chrono::Utc::now())?
        .map(|entry| entry.outcome.governance_binding)
        .ok_or_else(|| "MLS authoring result is missing or stale".to_owned())
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

/// Read the exact accepted MLS epoch CAS head from the own-Station result.
/// A producer must bind a Commit's
/// `head_eq` predicate to this whole registered value; the scalar epoch is
/// only one member of that value and is not a Cell head.
pub(crate) async fn station_mls_epoch_head(
    state_store: &crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    mls_group_id: &str,
) -> Result<serde_json::Value, String> {
    let local = state_store.load();
    for entry in local.mls_governance_results.values() {
        if &entry.request.effective_scope == effective_scope
            && entry.request.mls_group_id.as_str() == mls_group_id
        {
            if let Some(entry) = state_store
                .cached_mls_governance_result_entry(&entry.request, chrono::Utc::now())?
            {
                if let Some(head) = entry.outcome.epoch_head {
                    return serde_json::to_value(head).map_err(|error| error.to_string());
                }
            }
        }
    }
    Err("MLS authoring requires the Station's exact current epoch head".to_owned())
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
        return Ok(arkret_sdk::ActorId::service(claim.principal_id.clone()));
    }
    // Agent and human-device claims produce the same account ActorId. An Agent
    // is a Station-carried account (`client-preferences.md` "actor" targets),
    // and `validate_target_claim_evidence` above has already refused any Agent
    // claim whose `agent_id` is not literally `principal_id`, so there is no
    // second principal to project here.
    Ok(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        claim.principal_id.clone(),
        receipt.destination_id.clone(),
    )))
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
            arkret_sdk::MlsWelcomeRecipient::Agent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
        ) if principal_id == recipient_agent_id => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::agent_runtime(
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
        arkret_sdk::MlsRequesterTrustBinding::RequesterAgent {
            requester_agent_id,
            requester_agent_verification_method,
            requester_agent_key_authorize_event_id,
        } => MlsLeafAuthorityHint {
            endpoint: arkret_sdk::MlsEndpointIdentity::agent_runtime(
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
    let accepted_leaves = state
        .mls_accepted_artifacts
        .values()
        .filter_map(|entry| state_store.cached_mls_accepted_artifact(&entry.event.event_id))
        .find(|entry| {
            &entry.outcome.governance_binding == binding
                && entry.request.mls_group_id.as_str() == group.group_id()
                && entry.outcome.transition_head.next_epoch == group.epoch()
        })
        .map(|entry| entry.outcome.mls_frontier_leaves);
    let frontier_leaves = match accepted_leaves {
        Some(leaves) => leaves,
        None => {
            let mut matches = state
                .mls_governance_results
                .values()
                .filter(|entry| {
                    &entry.outcome.governance_binding == binding
                        && entry.request.mls_group_id.as_str() == group.group_id()
                        && entry.request.next_epoch == group.epoch()
                })
                .filter_map(|entry| {
                    state_store
                        .cached_mls_governance_result_entry(&entry.request, chrono::Utc::now())
                        .transpose()
                });
            let entry = matches
                .next()
                .transpose()?
                .ok_or_else(|| "MLS transition has no Station leaf input".to_owned())?;
            if matches.next().is_some() {
                return Err("MLS transition has conflicting leaf inputs".to_owned());
            }
            entry.request.local_mls_leaves.clone()
        }
    };

    let author_leaves = group
        .active_author_leaves()
        .into_iter()
        .map(|leaf| (leaf.leaf_index, leaf))
        .collect::<BTreeMap<_, _>>();
    if author_leaves.len() != frontier_leaves.len() {
        return Err(
            "accepted transition leaf set does not cover the post-transition MLS tree".to_owned(),
        );
    }
    let retained_bindings = group
        .retained_verified_leaf_bindings()
        .map_err(|error| format!("read retained MLS leaf bindings: {error}"))?
        .into_iter()
        .map(|binding| (binding.leaf_index, binding))
        .collect::<BTreeMap<_, _>>();
    let mut installed = Vec::with_capacity(author_leaves.len());
    for frontier_leaf in &frontier_leaves {
        let author_leaf = author_leaves
            .get(&frontier_leaf.leaf_index)
            .ok_or_else(|| "accepted transition leaf set names an empty MLS leaf".to_owned())?;
        let arkret_sdk::AuthorLeafCredential::Basic { identity } = &author_leaf.credential else {
            return Err("accepted Arkret MLS leaf does not use BasicCredential".to_owned());
        };
        if identity.as_slice() != frontier_leaf.credential_ref.as_bytes() {
            return Err(
                "accepted transition credential differs from the post-transition leaf".to_owned(),
            );
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
                return Err(
                    "retained MLS authority differs from the accepted transition leaf".to_owned(),
                );
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
                return Err("ordinary MLS leaf has duplicate authority hints".to_owned());
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
                        return Err("ordinary MLS leaf has no Station device authority".to_owned());
                    }
                };
                if cached_key
                    .ed25519_bytes()
                    .map_err(|error| format!("invalid cached device authority key: {error}"))?
                    != signature_key
                {
                    return Err(
                        "ordinary MLS leaf key differs from its Station device authority"
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
                return Err("Agent MLS credential differs from its principal".to_owned());
            }
            let mut hints = authority_hints.iter().filter(|hint| {
                matches!(
                    &hint.endpoint,
                    arkret_sdk::MlsEndpointIdentity::AgentRuntime { agent_id, .. }
                        if agent_id == frontier_leaf.actor_id.signing_principal_id()
                )
            });
            let hint = hints
                .next()
                .ok_or_else(|| "Agent MLS leaf has no verified authority hint".to_owned())?;
            if hints.next().is_some() {
                return Err("Agent MLS leaf has duplicate authority hints".to_owned());
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

#[cfg(test)]
pub(crate) fn seed_test_governance_result(
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
    let proposed_group_genesis_binding = if previous_epoch == 0 && next_epoch == 0 {
        proposed_group_genesis_binding(state_store, &effective_scope).ok()
    } else {
        None
    };
    let request = arkret_sdk::MlsGovernanceFrontierRequestBody {
        effective_scope,
        mls_group_id,
        local_mls_leaves: seed_test_security_frontier_leaves(),
        seal_basis: basis.clone(),
        base_group_state_ref,
        proposed_group_genesis_binding,
        previous_epoch,
        next_epoch,
    };
    request.validate().unwrap();
    let root = arkret_sdk::Hash::new(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    let genesis_binding = request
        .proposed_group_genesis_binding
        .as_ref()
        .map(arkret_sdk::MlsGroupGenesisBinding::from_proposal)
        .transpose()
        .unwrap()
        .unwrap_or(arkret_sdk::MlsGroupGenesisBinding {
            content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
            durability_policy: None,
        });
    let binding =
        binding_from_station_fixture(&request, root.clone(), &genesis_binding, None).unwrap();
    let epoch_head =
        request
            .base_group_state_ref
            .as_ref()
            .map(|reference| arkret_sdk::MlsEpochHead {
                transition_ref: reference.clone(),
                transition_event_digest: reference.event_digest(),
                mls_transition_digest: reference.event_digest(),
                effective_scope: request.effective_scope.clone(),
                mls_group_id: request.mls_group_id.clone(),
                previous_epoch: previous_epoch.saturating_sub(1),
                next_epoch: previous_epoch,
                content_scheme: binding.content_scheme(),
            });
    let result = arkret_sdk::MlsGovernanceFrontierOutcome {
        query_digest: request.query_digest().unwrap(),
        live_digest_suite: arkret_sdk::DigestSuite::Sha256,
        governance_binding: binding.clone(),
        epoch_head,
    };
    state_store
        .cache_mls_governance_result(request, result)
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

#[cfg(test)]
fn binding_from_station_fixture(
    request: &arkret_sdk::MlsGovernanceFrontierRequestBody,
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
        .mls_checkpoint_for_scope(effective_scope)
        .ok_or_else(|| "MLS security frontier requires a local group snapshot".to_owned())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = crate::mls::runtime::load_device_checkpoint_secret(
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
        .mls_checkpoint_for_scope(effective_scope)
        .ok_or_else(|| "MLS security frontier requires a local group snapshot".to_owned())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = crate::mls::runtime::load_device_checkpoint_secret(
        secure_store.as_ref(),
        authority,
        device_id,
    )
    .map_err(|error| format!("load MLS snapshot secret for Add preview: {error}"))?;
    let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0)
        .map_err(|error| format!("restore MLS group for Add preview: {error}"))?;
    group
        .preview_member_admission_security_frontier(
            records,
            actors,
            effective_scope.realm_id_opt().is_some_and(|realm| {
                state_store.realm_collaboration_role(realm.as_str())
                    == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
            }),
        )
        .map_err(|error| format!("stage exact MLS Add frontier: {error}"))
}

pub(crate) fn security_frontier_without_leaves(
    mut leaves: Vec<arkret_sdk::MlsSecurityFrontierLeaf>,
    removed: &[u32],
) -> Vec<arkret_sdk::MlsSecurityFrontierLeaf> {
    let removed = removed.iter().collect::<BTreeSet<_>>();
    leaves.retain(|leaf| !removed.contains(&leaf.leaf_index));
    leaves
}

#[cfg(test)]
mod removal_frontier_tests {
    use super::*;

    #[test]
    fn removing_one_leaf_preserves_another_leaf_for_the_same_actor() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actors = ["alpha.example", "alpha.example"].map(|station| {
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
        let retained = security_frontier_without_leaves(leaves, &[0]);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].actor_id, actors[1]);
        assert_eq!(retained[0].leaf_index, 1);
    }
}

#[cfg(test)]
mod direct_conversation_genesis_tests {
    use serde_json::json;

    use super::*;

    fn projection() -> serde_json::Value {
        json!({"state": {"events": [{
            "kind": "ak.realm.create",
            "payload": {"object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "direct_conversation",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1", "ak.profile.direct_conversation_realm.v1"],
                "reducer_profile": "ak.reducer.core.v1",
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "encryption_profile": "mls_rfc9420",
                "notary": {"kind": "single_signer", "signer": {
                    "actor_id": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:web:alice.example",
                        "station_id": "ak:did_core:web:station.example"
                    }},
                    "verification_method": "did:web:alice.example#key-1",
                    "key_kind": "ed25519_raw32", "jose_algorithm": "Ed25519",
                    "frozen_public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "frozen_public_key_digest": "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
                }}
            }}
        }]}})
    }

    #[test]
    fn direct_conversation_genesis_proposes_exporter_without_claiming_accepted_binding() {
        let projection = projection();
        let proposal = direct_conversation_genesis_proposal(&projection).unwrap();
        proposal.validate().unwrap();
        assert_eq!(
            proposal.content_scheme,
            arkret_wire::ContentScheme::MlsExporterAeadV1
        );
        assert_eq!(
            proposal.durability_policy,
            Some(arkret_wire::DurabilityPolicy::None)
        );
        assert_eq!(
            crate::realm_tree::realm_projection_content_scheme(&projection),
            None
        );
        assert!(crate::realm_tree::realm_projection_group_genesis_binding(&projection).is_none());
    }

    #[test]
    fn direct_conversation_genesis_requires_both_canonical_purpose_and_profile() {
        let mut wrong_purpose = projection();
        wrong_purpose["state"]["events"][0]["payload"]["object"]["purpose"] =
            json!("collaboration");
        assert!(direct_conversation_genesis_proposal(&wrong_purpose).is_none());
        let mut missing_profile = projection();
        missing_profile["state"]["events"][0]["payload"]["object"]["schema_refs"] =
            json!(["ak.schema.realm.v1"]);
        assert!(direct_conversation_genesis_proposal(&missing_profile).is_none());
        assert!(
            direct_conversation_genesis_proposal(&json!({"purpose":"direct_conversation"}))
                .is_none()
        );
    }
}
