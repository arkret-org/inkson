use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::mls::persistence::MlsLocalCheckpointEnvelope;
use crate::operation::trim_realm_id;
use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

/// One Welcome, waiting only for the Commit's final identity.
///
/// A Welcome payload carries `commit_ref`, which is the Commit's `event_id`, so
/// the Welcome cannot exist until the Commit is authored. Handing back a step
/// instead of a finished Event is what makes that ordering unavoidable: the
/// previous shape built both against a draft id and then rewrote the Welcomes
/// once the Commit's real id appeared.
pub(crate) type WelcomeIntentStep =
    Box<dyn FnOnce(&arkret_sdk::EventId) -> Result<crate::operation::EventIntent, String> + Send>;

pub(crate) struct RealmMlsAdmissionEvents {
    pub(crate) commit: MlsAdmissionAuthoringPlan,
    pub(crate) welcome: WelcomeIntentStep,
    pub(crate) snapshot: MlsLocalCheckpointEnvelope,
}

#[derive(Clone)]
pub(crate) struct MlsAdmissionAuthoringPlan {
    proposals: Vec<crate::operation::LocalOperation>,
    commit_basis: crate::mls::group_events::MlsCommitBasis,
}

impl MlsAdmissionAuthoringPlan {
    pub(crate) fn authoring_steps(&self) -> Vec<crate::event_submit::EventUnitStep> {
        let proposals = self
            .proposals
            .clone()
            .into_iter()
            .map(crate::operation::LocalOperation::into_intent)
            .collect::<Vec<_>>();
        let expected_proposals = proposals.len();
        let commit_basis = self.commit_basis.clone();
        vec![
            Box::new(move |_| Ok(proposals)),
            Box::new(move |authored| {
                if authored.len() != expected_proposals
                    || authored
                        .iter()
                        .any(|event| event.kind != arkret_sdk::EventKind::MlsProposal)
                {
                    anyhow::bail!("MLS admission Commit did not receive its exact proposal unit");
                }
                let proposal_refs = authored
                    .iter()
                    .map(|event| event.event_id().clone())
                    .collect();
                Ok(vec![
                    commit_basis
                        .build(proposal_refs)
                        .map_err(anyhow::Error::msg)?
                        .into_intent(),
                ])
            }),
        ]
    }

    pub(crate) fn transaction_id(&self) -> Result<&str, String> {
        self.proposals
            .first()
            .map(|proposal| proposal.local_operation_id().as_str())
            .ok_or_else(|| "MLS admission plan has no proposal".to_owned())
    }
}

pub(crate) struct WelcomePayloadInputs {
    pub(crate) realm_id: String,
    pub(crate) actor_id: String,
    /// The closed account of the ordinary requester (this client's
    /// authority). The Device branch names it in the Welcome claim envelope;
    /// it is never rebuilt from `actor_id` plus the ambient Station.
    pub(crate) requester_account_id: arkret_sdk::AccountId,
    pub(crate) requester: WelcomeRequester,
    pub(crate) claim: arkret_sdk::KeyPackageClaimRecord,
    pub(crate) keypackage_id: String,
    pub(crate) welcome_envelope: arkret_sdk::MlsWelcomeEnvelope,
    pub(crate) governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    pub(crate) claim_receipt: arkret_sdk::PeerKeyPackageClaimReceipt,
    pub(crate) effective_scope: Option<arkret_sdk::ScopeRef>,
}

#[derive(Clone)]
pub(crate) enum WelcomeRequester {
    Device {
        sender_device_id: arkret_sdk::DeviceId,
        requester_device_authorize_event_id: arkret_sdk::EventId,
    },
    MinimalMetadataPairwise {
        verification_method: arkret_sdk::DidUrl,
        signer: std::sync::Arc<crate::event_signer::InksonEventSigner>,
    },
}

fn admission_actor_and_requester(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    ordinary_actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: Option<&arkret_sdk::EventId>,
) -> Result<(String, WelcomeRequester), String> {
    if state_store.realm_projection_is_minimal_metadata(realm_id) {
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("invalid minimal-metadata Realm id: {error}"))?;
        let material = crate::mls::pairwise_identity::derive_pairwise_signing_material(
            authority, device_id, &realm_id,
        )?;
        let verification_method =
            arkret_sdk::DidUrl::new(material.signer.verification_method().to_owned())
                .map_err(|error| format!("invalid pairwise verification method: {error}"))?;
        return Ok((
            material.actor_id.to_string(),
            WelcomeRequester::MinimalMetadataPairwise {
                verification_method,
                signer: material.signer.clone(),
            },
        ));
    }
    let requester_device_authorize_event_id = requester_device_authorize_event_id
        .cloned()
        .ok_or_else(|| {
            "ordinary MLS admission requires the current requester device authorization Event"
                .to_owned()
        })?;
    Ok((
        ordinary_actor_id.to_owned(),
        WelcomeRequester::Device {
            sender_device_id: device_id.clone(),
            requester_device_authorize_event_id,
        },
    ))
}

pub(crate) async fn current_requester_device_authorize_event_id(
    http: &arkret_sdk::http_client::Client,
    device_id: &str,
) -> Result<arkret_sdk::EventId, String> {
    let device_id = arkret_sdk::DeviceId::new(device_id.trim().to_owned())
        .map_err(|error| format!("invalid requester device id: {error}"))?;
    let account = crate::transport::keys::list_devices(http)
        .await
        .map_err(|error| format!("load current device authorization: {error}"))?;
    account
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .and_then(|device| device.authorized_event_ref)
        .ok_or_else(|| {
            "current requester device has no accepted device.authorize Event; Welcome authoring is fail-closed"
                .to_owned()
        })
}

async fn current_authorization_incarnation(
    http: &arkret_sdk::http_client::Client,
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    target: &arkret_sdk::ActorId,
) -> Result<arkret_sdk::AuthorizationIncarnation, String> {
    let epoch = crate::identity::device_directory::cache_epoch();
    let request = arkret_sdk::MembershipAuthorityRequest {
        effective_scope: arkret_sdk::HistoryEffectiveScope::Realm {
            realm_id: realm_id
                .parse()
                .map_err(|error| format!("invalid admission Realm: {error}"))?,
        },
        actor_id: target.clone(),
        seal_basis: arkret_sdk::SealBasis {
            leaves: state_store
                .seal_view_for_realm(realm_id)
                .frontier
                .iter()
                .map(|leaf| {
                    leaf.parse()
                        .map_err(|error| format!("invalid admission frontier: {error}"))
                })
                .collect::<Result<_, _>>()?,
        },
    };
    let outcome = http
        .membership_authority(&request)
        .await
        .map_err(|error| error.to_string())?;
    outcome
        .validate_for_account(&request, authority)
        .map_err(|error| error.to_string())?;
    if epoch != crate::identity::device_directory::cache_epoch() {
        return Err("account session changed during MLS membership query".to_owned());
    }
    Ok(outcome.authorization_incarnation)
}

fn build_endpoint_admission_proposal_event(
    realm_id: &str,
    effective_scope: Option<&arkret_sdk::ScopeRef>,
    actor_id: &str,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    target_actor: &arkret_sdk::ActorId,
    proposal: &arkret_sdk::MlsProposalEnvelope,
    target_authorization_incarnation: arkret_sdk::AuthorizationIncarnation,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<crate::operation::LocalOperation, String> {
    let proposal_type = match proposal.proposal_type.as_str() {
        "add" => arkret_sdk::MlsProposalType::Add,
        "remove" => arkret_sdk::MlsProposalType::Remove,
        _ => return Err("MLS endpoint admission requires Add or Remove".to_owned()),
    };
    match (
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(_), None, None, None) => {}
        (None, Some(agent_id), Some(_), Some(_)) if agent_id == &claim.principal_id => {}
        _ => return Err("MLS admission claim has an invalid Human/Agent branch".to_owned()),
    }
    let payload = arkret_sdk::MlsProposalPayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(proposal.group_id.clone())
            .map_err(|error| format!("invalid MLS proposal group id: {error}"))?,
        base_epoch: proposal.epoch,
        proposal_type,
        proposal_bytes_b64: proposal.proposal.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        target_actor_id: Some(target_actor.clone()),
        target_authorization_incarnation: (proposal_type == arkret_sdk::MlsProposalType::Add)
            .then_some(target_authorization_incarnation),
        governance_binding,
    };
    let mut builder = crate::operation::ak_ops::mls_proposal_with_governance(
        realm_id,
        actor_id,
        &proposal.group_id,
        &payload,
    )
    .map_err(|error| format!("MLS Add proposal payload failed: {error}"))?;
    if let Some(effective_scope) = effective_scope {
        builder = builder.effective_scope(effective_scope.clone());
    }
    builder
        .build_sdk_event("inkson")
        .map_err(|error| format!("MLS Add proposal SDK Event conversion failed: {error}"))
}

pub(crate) async fn build_realm_mls_admission_events_from_claim(
    http: &arkret_sdk::http_client::Client,
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: Option<&arkret_sdk::EventId>,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    build_realm_mls_admission_events_from_verified_claim(
        http,
        state_store,
        secure_store,
        realm_id,
        authority,
        actor_id,
        device_id,
        requester_device_authorize_event_id,
        claim,
        claim_request_id,
        claim_receipt,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn build_realm_mls_admission_events_from_verified_claim(
    http: &arkret_sdk::http_client::Client,
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: Option<&arkret_sdk::EventId>,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    let (actor_id, requester) = admission_actor_and_requester(
        state_store,
        realm_id,
        authority,
        actor_id,
        device_id,
        requester_device_authorize_event_id,
    )?;
    validate_claim_receipt_for_admission(
        state_store,
        realm_id,
        authority,
        claim,
        claim_request_id,
        claim_receipt,
    )?;
    let target_actor = crate::mls::governance_proof::claimed_actor_id(claim, claim_receipt)?;
    let target_authorization_incarnation =
        current_authorization_incarnation(http, state_store, realm_id, authority, &target_actor)
            .await?;
    let member_key_package = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))?;
    let member_authority_hint =
        crate::mls::governance_proof::leaf_authority_hint_from_claim(claim)?;
    let (add, snapshot, previous_governance_binding) =
        crate::mls::runtime::build_add_member_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            None,
            authority,
            device_id,
            &member_key_package,
            &member_authority_hint,
        )
        .map_err(|err| err.user_message())?;
    let commit_basis = crate::mls::group_events::mls_commit_basis_from_store(
        state_store,
        realm_id,
        None,
        &actor_id,
        &add.commit,
        &previous_governance_binding,
        None,
    )
    .await?;
    let proposals = add
        .proposals
        .iter()
        .map(|proposal| {
            build_endpoint_admission_proposal_event(
                realm_id,
                None,
                &actor_id,
                claim,
                &target_actor,
                proposal,
                target_authorization_incarnation.clone(),
                commit_basis.governance_binding().clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let governance_binding = commit_basis.governance_binding().clone();
    let welcome_inputs = WelcomePayloadInputs {
        realm_id: realm_id.to_owned(),
        actor_id,
        requester_account_id: authority.clone(),
        requester,
        claim: claim.clone(),
        keypackage_id: member_key_package.keypackage_id.clone(),
        welcome_envelope: add.welcome.clone(),
        governance_binding,
        claim_receipt: claim_receipt.clone(),
        effective_scope: None,
    };
    Ok(RealmMlsAdmissionEvents {
        commit: MlsAdmissionAuthoringPlan {
            proposals,
            commit_basis,
        },
        welcome: welcome_intent_step(welcome_inputs),
        snapshot,
    })
}

fn validate_claim_receipt_for_admission(
    state_store: &LocalStateStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<(), String> {
    let expected_realm = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|error| format!("invalid admission realm_id: {error}"))?;
    // The receipt names the requester as a complete account; it is compared as
    // one value, never by principal alone (account-lifecycle.md §156).
    if receipt.request.requester_account_id.as_ref() != Some(authority)
        || receipt.request.target_principal_id().as_ref() != Some(&claim.principal_id)
        || receipt.request.intended_realm_id != expected_realm
        || receipt.request.claim_request_id.as_str() != claim_request_id
    {
        return Err(
            "KeyPackage claim receipt does not match the exact requester, target, Realm, MLS group, and claim request id"
                .to_owned(),
        );
    }
    let expected_group = state_store
        .mls_checkpoint_for(realm_id)
        .map(|snapshot| snapshot.group_id)
        .ok_or_else(|| "MLS admission requires a current local group snapshot".to_owned())?;
    if receipt.request.mls_group_id.as_str() != expected_group {
        return Err("KeyPackage claim receipt MLS group does not match local state".to_owned());
    }
    arkret_sdk::validate_target_claim_evidence(claim, receipt).map_err(|error| {
        format!("KeyPackage claim did not satisfy its exact target selector: {error}")
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn welcome_intent_step(inputs: WelcomePayloadInputs) -> WelcomeIntentStep {
    Box::new(move |commit_event_id| {
        let payload = match &inputs.requester {
            WelcomeRequester::Device {
                sender_device_id,
                requester_device_authorize_event_id,
            } => build_mls_welcome_payload(
                &inputs.realm_id,
                &inputs.actor_id,
                &inputs.requester_account_id,
                sender_device_id.as_str(),
                requester_device_authorize_event_id,
                &inputs.claim,
                &inputs.keypackage_id,
                &inputs.welcome_envelope,
                commit_event_id,
                inputs.governance_binding,
                &inputs.claim_receipt,
            ),
            WelcomeRequester::MinimalMetadataPairwise {
                verification_method,
                signer,
            } => build_pairwise_mls_welcome_payload(
                &inputs.realm_id,
                &inputs.actor_id,
                verification_method,
                signer.as_ref(),
                &inputs.claim,
                &inputs.keypackage_id,
                &inputs.welcome_envelope,
                commit_event_id,
                inputs.governance_binding,
                &inputs.claim_receipt,
            ),
        }?;
        let mut builder = crate::operation::ak_ops::mls_welcome_with_governance(
            &inputs.realm_id,
            &inputs.actor_id,
            &inputs.welcome_envelope.group_id,
            &payload,
        )
        .map_err(|err| format!("MLS Welcome typed payload conversion failed: {err}"))?;
        if let Some(effective_scope) = inputs.effective_scope {
            builder = builder.effective_scope(effective_scope);
        }
        builder
            .build_sdk_event("inkson")
            .map(crate::operation::LocalOperation::into_intent)
            .map_err(|err| format!("MLS Welcome SDK Event conversion failed: {err}"))
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_mls_welcome_payload(
    realm_id: &str,
    actor_id: &str,
    requester_account_id: &arkret_sdk::AccountId,
    sender_device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    _key_package_id: &str,
    welcome: &arkret_sdk::MlsWelcomeEnvelope,
    commit_event_id: &arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::MlsWelcomePayload, String> {
    build_mls_welcome_payload_with_requester(
        realm_id,
        WelcomeRequesterRef::Device {
            actor_id,
            account_id: requester_account_id,
            sender_device_id,
            requester_device_authorize_event_id,
        },
        claim,
        _key_package_id,
        welcome,
        commit_event_id,
        governance_binding,
        claim_receipt,
    )
}

/// Build the same canonical Welcome payload for a pairwise requester. The
/// caller supplies the exact persisted MLS identity that owns the did:key;
/// transport session identity is deliberately outside this authoring API.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pairwise_mls_welcome_payload(
    realm_id: &str,
    requester_actor_id: &str,
    requester_verification_method: &arkret_sdk::DidUrl,
    requester_signer: &crate::event_signer::InksonEventSigner,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    key_package_id: &str,
    welcome: &arkret_sdk::MlsWelcomeEnvelope,
    commit_event_id: &arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::MlsWelcomePayload, String> {
    build_mls_welcome_payload_with_requester(
        realm_id,
        WelcomeRequesterRef::MinimalMetadataPairwise {
            actor_id: requester_actor_id,
            verification_method: requester_verification_method,
            signer: requester_signer,
        },
        claim,
        key_package_id,
        welcome,
        commit_event_id,
        governance_binding,
        claim_receipt,
    )
}

enum WelcomeRequesterRef<'a> {
    Device {
        actor_id: &'a str,
        account_id: &'a arkret_sdk::AccountId,
        sender_device_id: &'a str,
        requester_device_authorize_event_id: &'a arkret_sdk::EventId,
    },
    MinimalMetadataPairwise {
        actor_id: &'a str,
        verification_method: &'a arkret_sdk::DidUrl,
        signer: &'a crate::event_signer::InksonEventSigner,
    },
}

#[allow(clippy::too_many_arguments)]
fn build_mls_welcome_payload_with_requester(
    realm_id: &str,
    requester: WelcomeRequesterRef<'_>,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    _key_package_id: &str,
    welcome: &arkret_sdk::MlsWelcomeEnvelope,
    commit_event_id: &arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::MlsWelcomePayload, String> {
    let intended_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS Welcome Realm id: {err:?}"))?;
    let (requester_did, requester_account_id, sender_device_id, trust_binding, pairwise_identity) =
        match requester {
            WelcomeRequesterRef::Device {
                actor_id,
                account_id,
                sender_device_id,
                requester_device_authorize_event_id,
            } => {
                let requester_did =
                    crate::mls_api_helpers::principal_core_id(actor_id).map_err(|err| {
                        format!("invalid MLS Welcome requester principal core id: {err:?}")
                    })?;
                if requester_did != account_id.principal_id {
                    return Err(
                        "MLS Welcome requester actor does not belong to the supplied account"
                            .to_owned(),
                    );
                }
                let sender_device_id =
                    arkret_sdk::DeviceId::new(sender_device_id.trim().to_owned())
                        .map_err(|err| format!("invalid MLS Welcome sender device id: {err:?}"))?;
                (
                    requester_did,
                    Some(account_id.clone()),
                    Some(sender_device_id.clone()),
                    arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
                        requester_device_id: sender_device_id,
                        requester_device_authorize_event_id: requester_device_authorize_event_id
                            .clone(),
                    },
                    None,
                )
            }
            WelcomeRequesterRef::MinimalMetadataPairwise {
                actor_id,
                verification_method,
                signer,
            } => {
                let pairwise_actor_id = crate::mls_api_helpers::principal_core_id(actor_id)
                    .map_err(|error| format!("invalid pairwise requester actor id: {error}"))?;
                let expected_controller = arkret_sdk::project_did_to_core_id(
                    &arkret_sdk::Did::new(
                        verification_method
                            .as_str()
                            .split('#')
                            .next()
                            .unwrap_or_default()
                            .to_owned(),
                    )
                    .map_err(|error| format!("invalid pairwise requester controller: {error}"))?,
                )
                .map_err(|error| format!("invalid pairwise requester projection: {error}"))?;
                if expected_controller != pairwise_actor_id
                    || signer.verification_method() != verification_method.as_str()
                {
                    return Err(
                        "pairwise Welcome requester actor/method/signer mismatch".to_owned()
                    );
                }
                (
                    pairwise_actor_id,
                    None,
                    None,
                    arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                        requester_pairwise_verification_method: verification_method.clone(),
                    },
                    Some(signer),
                )
            }
        };
    let keypackage_bytes = arkret_sdk::base64url_decode(claim.keypackage.as_bytes())
        .map_err(|err| format!("invalid claimed KeyPackage bytes: {err}"))?;
    let keypackage_digest =
        arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&keypackage_bytes))
            .map_err(|err| format!("invalid claimed KeyPackage digest: {err}"))?;
    let capabilities_bytes = arkret_sdk::canonical::canonical_json_bytes(&claim.capabilities)
        .map_err(|err| format!("invalid claimed KeyPackage capabilities: {err}"))?;
    let capabilities_digest =
        arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&capabilities_bytes))
            .map_err(|err| format!("invalid claimed KeyPackage capabilities digest: {err}"))?;
    let requester_actor_id =
        match &trust_binding {
            arkret_sdk::MlsRequesterTrustBinding::RequesterDevice { .. } => {
                // The Device branch always carries the closed requester account
                // (matched above); it is the authority this client authors as.
                arkret_sdk::ActorId::account(requester_account_id.ok_or_else(|| {
                    "MLS Welcome device requester has no closed account".to_owned()
                })?)
            }
            arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise { .. } => {
                arkret_sdk::ActorId::service(requester_did.clone())
            }
            arkret_sdk::MlsRequesterTrustBinding::RequesterAgent { .. } => {
                arkret_sdk::ActorId::service(requester_did.clone())
            }
        };
    let envelope = arkret_sdk::UnsignedMlsWelcomeClaimEnvelope::new(
        arkret_sdk::MlsWelcomeClaimEnvelopeSigningInput {
            keypackage_ref: claim.keypackage_ref.clone(),
            keypackage_digest: keypackage_digest.clone(),
            intended_realm_id,
            claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
                .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
            requester_actor_id,
            trust_binding,
            welcome_digest: welcome.welcome_hash.clone(),
            created_at: crate::clock::now_utc_canonical(),
        },
        claim_receipt,
    )
    .map_err(|err| format!("invalid MLS Welcome claim receipt context: {err}"))?;
    let envelope = if let Some(signer) = pairwise_identity {
        sign_pairwise_welcome_claim_envelope(signer, envelope)?
    } else {
        let sender_device_id = sender_device_id
            .as_ref()
            .ok_or_else(|| "device Welcome requester is missing its sender device id".to_owned())?;
        let requester_actor_id = envelope.signing_input().requester_actor_id.clone();
        sign_welcome_claim_envelope(
            requester_actor_id.signing_principal_id().as_str(),
            sender_device_id.as_str(),
            envelope,
        )?
    };
    let claim_trust_binding = match (
        claim.device_authorize_event_id.as_ref(),
        claim.agent_key_authorize_event_id.as_ref(),
        claim.pairwise_verification_method.as_ref(),
    ) {
        (Some(event_id), None, None) => arkret_sdk::MlsClaimTrustBinding::DeviceAuthorizeEventId(
            arkret_sdk::NonEmptyString::new(event_id.as_str())
                .map_err(|err| format!("invalid device authorization event id: {err}"))?,
        ),
        (None, Some(event_id), None) => arkret_sdk::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(
            arkret_sdk::NonEmptyString::new(event_id.as_str())
                .map_err(|err| format!("invalid Agent key authorization event id: {err}"))?,
        ),
        (None, None, Some(method)) => arkret_sdk::MlsClaimTrustBinding::MinimalMetadataPairwise {
            pairwise_actor_id: claim.principal_id.clone(),
            pairwise_verification_method: method.clone(),
        },
        _ => return Err("MLS KeyPackage claim must contain exactly one trust binding".to_owned()),
    };
    let claim_ref = arkret_sdk::MlsWelcomePayloadClaimRef {
        claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
            .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest,
        capabilities_digest,
        trust_binding: claim_trust_binding,
    };
    let expires_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(claim.expires_at.timestamp(), 0)
            .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH);
    let recipient = match (
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(device_id), None, None, None) => arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id: device_id.clone(),
        },
        (None, Some(agent_id), Some(method), Some(authorize_event_id)) => {
            arkret_sdk::MlsWelcomeRecipient::Agent {
                recipient_agent_id: agent_id.clone(),
                recipient_agent_verification_method: method.clone(),
                agent_key_authorize_event_id: authorize_event_id.clone(),
            }
        }
        (None, None, None, None) => arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id: claim.principal_id.clone(),
            recipient_pairwise_verification_method: claim
                .pairwise_verification_method
                .clone()
                .ok_or_else(|| "pairwise KeyPackage claim omits its method".to_owned())?,
        },
        _ => return Err("MLS KeyPackage claim has an invalid recipient branch".to_owned()),
    };
    let expected_endpoint = match &recipient {
        arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => arkret_sdk::MlsEndpointIdentity::human_device(
            claim.principal_id.clone(),
            recipient_device_id.clone(),
        ),
        arkret_sdk::MlsWelcomeRecipient::Agent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => arkret_sdk::MlsEndpointIdentity::agent_runtime(
            recipient_agent_id.clone(),
            recipient_agent_verification_method.clone(),
            agent_key_authorize_event_id.clone(),
        )
        .map_err(|error| format!("invalid Agent Welcome endpoint: {error}"))?,
        arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } => arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
            recipient_pairwise_actor_id.clone(),
            recipient_pairwise_verification_method.clone(),
        )
        .map_err(|error| format!("invalid pairwise Welcome endpoint: {error}"))?,
    };
    if welcome.recipient != expected_endpoint {
        return Err(
            "MLS Welcome recipient differs from the admitted KeyPackage endpoint".to_owned(),
        );
    }
    let recipient_principal_id = if matches!(
        &recipient,
        arkret_sdk::MlsWelcomeRecipient::MinimalMetadataPairwise { .. }
    ) {
        None
    } else {
        Some(claim.principal_id.clone())
    };
    let payload = arkret_sdk::MlsWelcomePayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(welcome.group_id.clone())
            .map_err(|err| format!("invalid MLS Welcome group id: {err}"))?,
        epoch: welcome.epoch,
        recipient_principal_id,
        recipient,
        sender_device_id,
        keypackage_ref: claim.keypackage_ref.clone(),
        claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
            .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
        claim_ref,
        claim_envelope: envelope,
        claim_receipt: claim_receipt.clone(),
        carrier: arkret_sdk::MlsWelcomeCarrier::new(
            arkret_sdk::base64url_decode(welcome.welcome.as_bytes())
                .map_err(|err| format!("invalid MLS Welcome ciphertext: {err}"))?,
        )
        .map_err(str::to_owned)?,
        commit_ref: commit_event_id.clone(),
        governance_binding,
        expires_at,
    };
    Ok(payload)
}

fn sign_pairwise_welcome_claim_envelope(
    signer: &crate::event_signer::InksonEventSigner,
    envelope: arkret_sdk::UnsignedMlsWelcomeClaimEnvelope,
) -> Result<arkret_sdk::MlsWelcomeClaimEnvelope, String> {
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|error| format!("MLS Welcome pairwise canonical bytes: {error}"))?;
    let signature = signer
        .sign_raw(&signing_bytes)
        .map_err(|error| format!("MLS Welcome pairwise requester signature: {error}"))?;
    envelope
        .attach_signature(
            arkret_sdk::NonEmptyString::new(signer.verification_method())
                .map_err(|error| format!("MLS Welcome pairwise signature kid: {error}"))?,
            arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
                .map_err(|error| format!("MLS Welcome pairwise signature encoding: {error}"))?,
        )
        .map_err(|error| format!("MLS Welcome pairwise signed envelope: {error}"))
}

fn sign_welcome_claim_envelope(
    actor_id: &str,
    sender_device_id: &str,
    envelope: arkret_sdk::UnsignedMlsWelcomeClaimEnvelope,
) -> Result<arkret_sdk::MlsWelcomeClaimEnvelope, String> {
    let sender_device_id = sender_device_id.trim();
    if sender_device_id.is_empty() {
        return Err("MLS Welcome device signature requires sender_device_id".to_owned());
    }
    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("inkson")
            .map_err(|err| format!("MLS Welcome device signer bootstrap: {err}"))?,
    };
    let signer_did = arkret_sdk::Did::new(signer.signer_did().to_owned())
        .map_err(|err| format!("MLS Welcome signer DID: {err}"))?;
    let signer_actor_id = arkret_sdk::project_did_to_core_id(&signer_did)
        .map_err(|err| format!("MLS Welcome signer actor projection: {err}"))?;
    if signer_actor_id.as_str() != actor_id {
        return Err(
            "MLS Welcome active signer DID does not project to requester_actor_id".to_owned(),
        );
    }
    let expected_kid = format!("{signer_did}#{sender_device_id}");
    if signer.verification_method() != expected_kid {
        return Err(
            "MLS Welcome active signer verification method is not the exact requester device method"
                .to_owned(),
        );
    }
    let kid = arkret_sdk::NonEmptyString::new(expected_kid)
        .map_err(|err| format!("MLS Welcome device signing kid: {err}"))?;
    let signing_bytes = envelope
        .canonical_signing_bytes()
        .map_err(|err| format!("MLS Welcome claim canonical bytes: {err}"))?;
    let signature = signer
        .sign_raw(&signing_bytes)
        .map_err(|err| format!("MLS Welcome device signature: {err}"))?;
    let signature = arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
        .map_err(|err| format!("MLS Welcome device signature encoding: {err}"))?;
    envelope
        .attach_signature(kid, signature)
        .map_err(|err| format!("MLS Welcome signed envelope: {err}"))
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;
    use crate::state::isolated_store_for_tests;

    fn claim_from_key_package(
        record: &arkret_sdk::MlsKeyPackageRecord,
        device_authorize_event_id: &str,
    ) -> arkret_sdk::KeyPackageClaimRecord {
        let (principal_id, device_id) = match &record.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::AgentRuntime { .. }
            | arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                panic!("test fixture requires a human-device record")
            }
        };
        arkret_sdk::KeyPackageClaimRecord {
            claim_id: "keypackage-test:Y2xhaW0tbm9uY2U".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            principal_id: principal_id.clone(),
            device_id: Some(device_id),
            agent_id: None,
            agent_verification_method: None,
            pairwise_verification_method: None,
            keypackage: record.keypackage.clone(),
            capabilities: record.capabilities.clone(),
            device_authorize_event_id: Some(
                arkret_sdk::EventId::new(device_authorize_event_id.to_owned()).unwrap(),
            ),
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
            revocation_status: None,
            last_resort: None,
        }
    }

    fn self_claim_receipt(
        claim: &arkret_sdk::KeyPackageClaimRecord,
        realm_id: &str,
        requester: &str,
        claim_request_id: &str,
    ) -> arkret_sdk::PeerKeyPackageClaimReceipt {
        let request = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: arkret_sdk::Base64UrlString::new(claim_request_id.to_owned())
                .unwrap(),
            target_account_id: Some(arkret_sdk::AccountId::new(
                claim.principal_id.clone(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            )),
            intended_realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            requester_account_id: Some(arkret_sdk::AccountId::new(
                crate::mls_api_helpers::principal_core_id(requester).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            )),
            mls_group_id: arkret_sdk::NonEmptyString::new(
                garth::mls::welcome_admission::mls_group_id_for_realm(realm_id)
                    .expect("test Realm scope must derive a canonical MLS group id"),
            )
            .unwrap(),
            claim_purpose: arkret_sdk::PeerKeyPackageClaimPurpose::RealmMembership,
            required_capabilities: claim
                .capabilities
                .iter()
                .map(|value| arkret_sdk::NonEmptyString::new(value).unwrap())
                .collect(),
            expires_at: claim.expires_at,
            target_device_ids: claim.device_id.clone().into_iter().collect(),
            target_keypackage_ref: None,
            target_agent_id: None,
            target_agent_verification_method: None,
            target_agent_key_authorize_event_id: None,
            target_pairwise_verification_method: None,
            timeout_ms: None,
            strand_id: None,
            pair_key: None,
            last_resort_allowed: Some(false),
        };
        let request_digest =
            arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&request).unwrap())
                .unwrap();
        let claims_digest = arkret_sdk::Hash::new(
            arkret_sdk::canonical::canonical_sha256(&vec![claim.clone()]).unwrap(),
        )
        .unwrap();
        let authority = arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap();
        arkret_sdk::PeerKeyPackageClaimReceipt {
            claim_request_id: request.claim_request_id.clone(),
            request_digest,
            claims_digest,
            source_id: authority.clone(),
            destination_id: authority,
            request,
            claimed_at: crate::clock::now_utc(),
            expires_at: claim.expires_at,
            signature: arkret_sdk::KeyOperationSignature {
                kid: arkret_sdk::NonEmptyString::new("did:web:ps.example#assertion").unwrap(),
                signature_algorithm: Some(arkret_sdk::NonEmptyString::new("Ed25519").unwrap()),
                sig: arkret_sdk::Base64UrlString::new("YQ").unwrap(),
            },
        }
    }

    #[test]
    fn claimed_actor_uses_receipt_station_not_inviter_station() {
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1").unwrap(),
        )
        .unwrap();
        let claim = claim_from_key_package(
            &bob.key_package_record().unwrap(),
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        );
        let mut receipt = self_claim_receipt(&claim, realm, "did:web:alice.example", "Y2xhaW0");
        let alpha = crate::mls::governance_proof::claimed_actor_id(&claim, &receipt).unwrap();
        receipt.destination_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:beta.example").unwrap();
        let beta = crate::mls::governance_proof::claimed_actor_id(&claim, &receipt).unwrap();
        assert_eq!(alpha.signing_principal_id(), beta.signing_principal_id());
        assert_ne!(alpha, beta);
        assert_eq!(beta.route_service_id(), &receipt.destination_id);
    }

    fn welcome_authoring_receipt(claim_request_id: &str) -> arkret_sdk::PeerKeyPackageClaimReceipt {
        let claim = arkret_sdk::KeyPackageClaimRecord {
            claim_id: "keypackage-test:welcome-authoring".to_owned(),
            keypackage_ref:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            principal_id: arkret_sdk::DidCoreId::new("ak:did_core:web:target.example".to_owned())
                .unwrap(),
            device_id: None,
            agent_id: None,
            agent_verification_method: None,
            pairwise_verification_method: None,
            keypackage: "YQ".to_owned(),
            capabilities: Vec::new(),
            device_authorize_event_id: None,
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
            revocation_status: None,
            last_resort: None,
        };
        self_claim_receipt(
            &claim,
            "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx",
            "did:web:alice.example",
            claim_request_id,
        )
    }

    fn add_proposal_fixture(
        realm_id: &str,
    ) -> (
        arkret_sdk::MlsProposalEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ) {
        let group_id = garth::mls::welcome_admission::mls_group_id_for_realm(realm_id).unwrap();
        let proposal_bytes = b"durable-add-proposal";
        (
            arkret_sdk::MlsProposalEnvelope {
                group_id: group_id.clone(),
                epoch: 7,
                proposal_type: "add".to_owned(),
                proposal: arkret_sdk::base64url_encode(proposal_bytes),
                proposal_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
                    proposal_bytes,
                ))
                .unwrap(),
                ratchet_tree: None,
            },
            arkret_sdk::MlsGovernanceBindingPayload::realm(
                arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
                &group_id,
                7,
                8,
                arkret_sdk::Hash::new(format!("sha256:{}", "a1".repeat(32))).unwrap(),
                arkret_sdk::ContentScheme::MlsExporterAeadV1,
                Some(arkret_sdk::DurabilityPolicy::None),
                "ak.profile.mls_governance.v1",
                "ak.profile.reducer.v1",
            )
            .unwrap(),
        )
    }

    #[test]
    fn human_and_agent_adds_bind_the_exact_authorization_incarnation() {
        let realm = "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
        let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1".to_owned())
                .unwrap(),
        )
        .unwrap();
        let mut claim = claim_from_key_package(
            &bob.key_package_record().unwrap(),
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        );
        let (proposal, binding) = add_proposal_fixture(realm);
        let incarnation = arkret_sdk::AuthorizationIncarnation::Realm {
            realm_membership_incarnation_ref: arkret_sdk::EventId::new(
                "ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc".to_owned(),
            )
            .unwrap(),
        };

        let human = build_endpoint_admission_proposal_event(
            realm,
            None,
            "did:web:alice.example",
            &claim,
            &crate::mls_api_helpers::local_account_actor_id(claim.principal_id.as_str()).unwrap(),
            &proposal,
            incarnation.clone(),
            binding.clone(),
        )
        .unwrap()
        .typed_payload::<arkret_wire::event_spec::MlsProposal>()
        .unwrap();
        assert_eq!(
            human.target_authorization_incarnation,
            Some(incarnation.clone())
        );
        assert_eq!(
            human.target_actor_id,
            Some(
                crate::mls_api_helpers::local_account_actor_id(claim.principal_id.as_str())
                    .unwrap()
            )
        );

        let mut remove = proposal.clone();
        remove.proposal_type = "remove".to_owned();
        let removal = build_endpoint_admission_proposal_event(
            realm,
            None,
            "did:web:alice.example",
            &claim,
            &crate::mls_api_helpers::local_account_actor_id(claim.principal_id.as_str()).unwrap(),
            &remove,
            incarnation.clone(),
            binding.clone(),
        )
        .unwrap()
        .typed_payload::<arkret_wire::event_spec::MlsProposal>()
        .unwrap();
        assert_eq!(removal.proposal_type, arkret_sdk::MlsProposalType::Remove);
        assert!(removal.target_authorization_incarnation.is_none());

        claim.device_id = None;
        claim.device_authorize_event_id = None;
        claim.agent_id = Some(claim.principal_id.clone());
        claim.agent_verification_method =
            Some(arkret_sdk::DidUrl::new("did:web:bob.example#runtime-1".to_owned()).unwrap());
        claim.agent_key_authorize_event_id = Some(
            arkret_sdk::EventId::new(
                "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq".to_owned(),
            )
            .unwrap(),
        );
        let native = build_endpoint_admission_proposal_event(
            realm,
            None,
            "did:web:alice.example",
            &claim,
            &arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                claim.principal_id.clone(),
                crate::operation::authoring_station_id().unwrap(),
            )),
            &proposal,
            incarnation.clone(),
            binding,
        )
        .unwrap()
        .typed_payload::<arkret_wire::event_spec::MlsProposal>()
        .unwrap();
        assert_eq!(native.target_authorization_incarnation, Some(incarnation));
        assert_eq!(
            native.target_actor_id,
            Some(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                claim.principal_id,
                crate::operation::authoring_station_id().unwrap()
            )))
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn welcome_signature_uses_active_device_signer() {
        let actor = "ak:did_core:web:alice.example";
        let actor_did = "did:web:alice.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let verification_method = format!("{actor_did}#{device}");
        let active_signer = std::sync::Arc::new(
            crate::event_signer::build_ed25519_signer_with_verification_method(
                [7u8; 32],
                actor_did,
                verification_method.clone(),
            ),
        );
        let _signer_guard =
            crate::event_signer::ActiveSignerTestGuard::replace(Some(active_signer));
        let claim_receipt = welcome_authoring_receipt("bm9uY2U");
        let envelope = arkret_sdk::UnsignedMlsWelcomeClaimEnvelope::new(
            arkret_sdk::MlsWelcomeClaimEnvelopeSigningInput {
                keypackage_ref:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                keypackage_digest: arkret_sdk::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                intended_realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx",
                )
                .unwrap(),
                claim_id: arkret_sdk::NonEmptyString::new("ak:mls:kp:test:nonce").unwrap(),
                requester_actor_id: crate::mls_api_helpers::local_account_actor_id(
                    "ak:did_core:web:alice.example",
                )
                .unwrap(),
                trust_binding: arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
                    requester_device_id: arkret_sdk::DeviceId::new(device).unwrap(),
                    requester_device_authorize_event_id: arkret_sdk::EventId::new(
                        "ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc",
                    )
                    .unwrap(),
                },
                welcome_digest: arkret_sdk::Hash::new(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                created_at: crate::clock::now_utc(),
            },
            &claim_receipt,
        )
        .unwrap();

        let envelope = sign_welcome_claim_envelope(actor, device, envelope).unwrap();

        assert_eq!(
            envelope
                .trust_binding
                .requester_device_id()
                .map(arkret_sdk::DeviceId::as_str),
            Some(device)
        );
        assert_eq!(envelope.signature.kid.as_str(), verification_method);
        assert!(!envelope.signature.sig.is_empty());
        assert!(!envelope.signature.sig.contains(['+', '/', '=']));
        assert!(
            URL_SAFE_NO_PAD
                .decode(envelope.signature.sig.as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn welcome_pairwise_signature_uses_the_exact_realm_local_method() {
        let realm = arkret_sdk::RealmId::new(
            "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx".to_owned(),
        )
        .unwrap();
        let material = crate::mls::pairwise_identity::pairwise_signing_material_for_test(&realm);
        let method =
            arkret_sdk::DidUrl::new(material.signer.verification_method().to_owned()).unwrap();
        let claim_receipt = welcome_authoring_receipt("cGFpcndpc2Utbm9uY2U");
        let envelope = arkret_sdk::UnsignedMlsWelcomeClaimEnvelope::new(
            arkret_sdk::MlsWelcomeClaimEnvelopeSigningInput {
                keypackage_ref:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                keypackage_digest: arkret_sdk::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                intended_realm_id: realm,
                claim_id: arkret_sdk::NonEmptyString::new("ak:mls:kp:test:pairwise").unwrap(),
                requester_actor_id: arkret_sdk::ActorId::service(material.actor_id.clone()),
                trust_binding:
                    arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise {
                        requester_pairwise_verification_method: method.clone(),
                    },
                welcome_digest: arkret_sdk::Hash::new(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                created_at: crate::clock::now_utc(),
            },
            &claim_receipt,
        )
        .unwrap();

        let signed =
            sign_pairwise_welcome_claim_envelope(material.signer.as_ref(), envelope).unwrap();
        assert_eq!(signed.signature.kid.as_str(), method.as_str());
        assert_eq!(
            signed.requester_actor_id.signing_principal_id(),
            &material.actor_id
        );
        assert!(matches!(
            signed.trust_binding,
            arkret_sdk::MlsRequesterTrustBinding::RequesterMinimalMetadataPairwise { .. }
        ));
        assert!(
            URL_SAFE_NO_PAD
                .decode(signed.signature.sig.as_bytes())
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mismatched_claim_target_cannot_authorize_welcome() {
        let alice_state = isolated_store_for_tests("peer-self-claim-fail-closed");
        let secure = MemorySecureKeyStore::new();
        let realm = "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
        let alice = "did:web:alice.example";
        let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let bob = "did:web:bob.example";
        let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b1";
        let bob_identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::mls_api_helpers::principal_core_id(bob).unwrap(),
            arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
        )
        .unwrap();
        let bob_key_package = bob_identity.key_package_record().unwrap();
        let claim = claim_from_key_package(
            &bob_key_package,
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        );
        let requester_device_authorize_event_id =
            arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                .unwrap();

        let claim_request_id = "Y2xhaW0tcmVxdWVzdC0wMTIzNDU2Nzg5";
        let mut claim_receipt = self_claim_receipt(&claim, realm, alice, claim_request_id);
        claim_receipt.request.target_account_id = Some(arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(alice).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        ));
        let authority = arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(alice).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        let alice_device = arkret_sdk::DeviceId::new(alice_device.to_owned()).unwrap();
        let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let error = build_realm_mls_admission_events_from_claim(
            &http,
            &alice_state,
            &secure,
            realm,
            &authority,
            alice,
            &alice_device,
            Some(&requester_device_authorize_event_id),
            &claim,
            claim_request_id,
            &claim_receipt,
        )
        .await
        .err()
        .expect("remote claim must fail before MLS state mutation");

        assert!(
            error.contains("does not match the exact requester"),
            "{error}"
        );
        assert!(alice_state.mls_checkpoint_for(realm).is_none());
    }
}
