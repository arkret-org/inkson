use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::mls::persistence::MlsSnapshotEnvelope;
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
    pub(crate) snapshot: MlsSnapshotEnvelope,
}

pub(crate) struct RealmMlsBatchAdmissionEvents {
    pub(crate) commit: MlsAdmissionAuthoringPlan,
    pub(crate) welcomes: Vec<WelcomeIntentStep>,
    pub(crate) snapshot: MlsSnapshotEnvelope,
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
    pub(crate) device_id: String,
    pub(crate) requester_device_authorize_event_id: arkret_sdk::EventId,
    pub(crate) claim: arkret_sdk::KeyPackageClaimRecord,
    pub(crate) keypackage_id: String,
    pub(crate) welcome_envelope: arkret_sdk::MlsWelcomeEnvelope,
    pub(crate) governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    pub(crate) claim_nonce: String,
    pub(crate) claim_receipt: arkret_sdk::PeerKeyPackageClaimReceipt,
    pub(crate) effective_scope: Option<arkret_sdk::ScopeRef>,
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

fn current_authorization_incarnation(
    state_store: &LocalStateStore,
    realm_id: &str,
    circle_id: Option<&str>,
    target: &arkret_sdk::DidCoreId,
) -> Result<arkret_sdk::AuthorizationIncarnation, String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS admission Realm id: {error}"))?;
    let checkpoint = state_store
        .trusted_mls_governance_checkpoint(realm_id.as_str())
        .ok_or_else(|| "MLS admission has no durable verified governance checkpoint".to_owned())?;
    if checkpoint.realm_id != realm_id {
        return Err("MLS admission checkpoint belongs to another Realm".to_owned());
    }
    let circle_id = circle_id
        .map(|circle_id| {
            arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| format!("invalid MLS admission Circle id: {error}"))
        })
        .transpose()?;
    arkret_sdk::current_authorization_incarnation_from_verified_checkpoint(
        &checkpoint,
        target,
        circle_id.as_ref(),
    )
    .map_err(|error| format!("derive current MLS Add authorization incarnation: {error}"))
}

fn build_add_proposal_event(
    realm_id: &str,
    effective_scope: Option<&arkret_sdk::ScopeRef>,
    actor_id: &str,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    proposal: &arkret_sdk::MlsProposalEnvelope,
    target_authorization_incarnation: arkret_sdk::AuthorizationIncarnation,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
) -> Result<crate::operation::LocalOperation, String> {
    if proposal.proposal_type != "add" {
        return Err("MLS admission received a non-Add proposal envelope".to_owned());
    }
    let target_device_id = match (
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(device_id), None, None, None) => Some(device_id.clone()),
        (None, Some(agent_id), Some(_), Some(_)) if agent_id == &claim.principal_id => None,
        _ => return Err("MLS admission claim has an invalid Human/Native Agent branch".to_owned()),
    };
    let payload = arkret_sdk::MlsProposalPayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(proposal.group_id.clone())
            .map_err(|error| format!("invalid MLS proposal group id: {error}"))?,
        base_epoch: proposal.epoch,
        proposal_type: arkret_sdk::MlsProposalType::Add,
        proposal_message_ref: None,
        proposal_digest: Some(proposal.proposal_digest.clone()),
        target_principal_id: Some(claim.principal_id.clone()),
        target_device_id,
        target_authorization_incarnation: Some(target_authorization_incarnation),
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

pub(crate) fn build_realm_mls_admission_events_from_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    validate_claim_receipt_for_admission(
        state_store,
        realm_id,
        actor_id,
        claim,
        claim_nonce,
        claim_receipt,
    )?;
    build_realm_mls_admission_events_from_verified_claim(
        state_store,
        secure_store,
        realm_id,
        authority,
        actor_id,
        device_id,
        requester_device_authorize_event_id,
        claim,
        claim_nonce,
        claim_receipt,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_realm_mls_admission_events_from_verified_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    let member_key_package = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))?;
    let (add, snapshot, previous_governance_binding) =
        crate::mls::runtime::build_add_member_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            None,
            authority,
            device_id,
            &member_key_package,
        )
        .map_err(|err| err.user_message())?;
    let commit_basis = crate::mls::group_events::mls_commit_basis_from_store(
        state_store,
        realm_id,
        None,
        actor_id,
        &add.commit,
        &previous_governance_binding,
        None,
    )?;
    let target_authorization_incarnation =
        current_authorization_incarnation(state_store, realm_id, None, &claim.principal_id)?;
    let proposal = build_add_proposal_event(
        realm_id,
        None,
        actor_id,
        claim,
        &add.proposal,
        target_authorization_incarnation,
        commit_basis.governance_binding().clone(),
    )?;
    let governance_binding = commit_basis.governance_binding().clone();
    let welcome_inputs = WelcomePayloadInputs {
        realm_id: realm_id.to_owned(),
        actor_id: actor_id.to_owned(),
        device_id: device_id.to_string(),
        requester_device_authorize_event_id: requester_device_authorize_event_id.clone(),
        claim: claim.clone(),
        keypackage_id: member_key_package.keypackage_id.clone(),
        welcome_envelope: add.welcome.clone(),
        governance_binding,
        claim_nonce: claim_nonce.to_owned(),
        claim_receipt: claim_receipt.clone(),
        effective_scope: None,
    };
    Ok(RealmMlsAdmissionEvents {
        commit: MlsAdmissionAuthoringPlan {
            proposals: vec![proposal],
            commit_basis,
        },
        welcome: welcome_intent_step(welcome_inputs),
        snapshot,
    })
}

pub(crate) fn build_realm_mls_admission_events_from_claims(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claims: &[(
        arkret_sdk::KeyPackageClaimRecord,
        String,
        arkret_sdk::PeerKeyPackageClaimReceipt,
    )],
) -> Result<RealmMlsBatchAdmissionEvents, String> {
    build_mls_admission_events_from_claims_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
        authority,
        actor_id,
        device_id,
        requester_device_authorize_event_id,
        claims,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_mls_admission_events_from_claims_for_effective_scope(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    circle_id: Option<&str>,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claims: &[(
        arkret_sdk::KeyPackageClaimRecord,
        String,
        arkret_sdk::PeerKeyPackageClaimReceipt,
    )],
    sidecar_binding: Option<arkret_sdk::SidecarMlsBinding>,
) -> Result<RealmMlsBatchAdmissionEvents, String> {
    if claims.is_empty() {
        return Err("MLS admission batch requires at least one claim".to_owned());
    }
    for (claim, claim_nonce, receipt) in claims {
        validate_claim_receipt_for_admission(
            state_store,
            realm_id,
            actor_id,
            claim,
            claim_nonce,
            receipt,
        )?;
    }
    let member_key_packages = claims
        .iter()
        .map(|(claim, ..)| {
            crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
                .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (add, snapshot, previous_governance_binding) =
        crate::mls::runtime::build_add_members_commit_for_effective_scope_with_binding(
            state_store,
            secure_store,
            realm_id,
            circle_id,
            authority,
            device_id,
            &member_key_packages,
            sidecar_binding.clone(),
        )
        .map_err(|err| err.user_message())?;
    if sidecar_binding.is_some() {
        return Err("v1 Sidecar Add has no target authorization incarnation branch".to_owned());
    }
    let commit_basis = crate::mls::group_events::mls_commit_basis_from_store(
        state_store,
        realm_id,
        circle_id,
        actor_id,
        &add.commit,
        &previous_governance_binding,
        None,
    )?;
    let governance_binding = commit_basis.governance_binding().clone();
    if add.welcomes.len() != claims.len() || add.proposals.len() != claims.len() {
        return Err("MLS batch add returned a mismatched Proposal/Welcome count".to_owned());
    }
    let effective_scope = if let Some(binding) = sidecar_binding.as_ref() {
        Some(arkret_sdk::ScopeRef::Sidecar {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid Sidecar MLS Realm id: {error}"))?,
            sidecar_id: binding.sidecar_id.clone(),
        })
    } else if let Some(circle_id) = circle_id {
        Some(crate::mls::group_events::circle_effective_scope(
            realm_id, circle_id,
        )?)
    } else {
        None
    };
    let mut proposals = Vec::with_capacity(claims.len());
    let mut welcomes = Vec::with_capacity(claims.len());
    for (
        ((claim, claim_nonce, claim_receipt), proposal_envelope),
        (member_key_package, welcome_envelope),
    ) in claims
        .iter()
        .zip(add.proposals.iter())
        .zip(member_key_packages.iter().zip(add.welcomes.iter()))
    {
        let target_authorization_incarnation = current_authorization_incarnation(
            state_store,
            realm_id,
            circle_id,
            &claim.principal_id,
        )?;
        proposals.push(build_add_proposal_event(
            realm_id,
            effective_scope.as_ref(),
            actor_id,
            claim,
            proposal_envelope,
            target_authorization_incarnation,
            governance_binding.clone(),
        )?);
        welcomes.push(welcome_intent_step(WelcomePayloadInputs {
            realm_id: realm_id.to_owned(),
            actor_id: actor_id.to_owned(),
            device_id: device_id.to_string(),
            requester_device_authorize_event_id: requester_device_authorize_event_id.clone(),
            claim: claim.clone(),
            keypackage_id: member_key_package.keypackage_id.clone(),
            welcome_envelope: welcome_envelope.clone(),
            governance_binding: governance_binding.clone(),
            claim_nonce: claim_nonce.to_owned(),
            claim_receipt: claim_receipt.clone(),
            effective_scope: effective_scope.clone(),
        }));
    }
    Ok(RealmMlsBatchAdmissionEvents {
        commit: MlsAdmissionAuthoringPlan {
            proposals,
            commit_basis,
        },
        welcomes,
        snapshot,
    })
}

fn validate_claim_receipt_for_admission(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_nonce: &str,
    receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<(), String> {
    let requester = crate::mls_api_helpers::principal_core_id(actor_id)
        .map_err(|error| format!("invalid requester actor_id: {error}"))?;
    let expected_realm = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|error| format!("invalid admission realm_id: {error}"))?;
    if receipt.request.requester != requester
        || receipt.request.target_principal_id != claim.principal_id
        || receipt.request.intended_realm_id != expected_realm
        || receipt.request.claim_nonce.as_str() != claim_nonce
    {
        return Err(
            "KeyPackage claim receipt does not match the exact requester, target, Realm, MLS group, and nonce"
                .to_owned(),
        );
    }
    let expected_group = state_store
        .mls_snapshot_for(realm_id)
        .map(|snapshot| snapshot.group_id)
        .ok_or_else(|| "MLS admission requires a current local group snapshot".to_owned())?;
    if receipt.request.mls_group_id.as_str() != expected_group {
        return Err("KeyPackage claim receipt MLS group does not match local state".to_owned());
    }
    if !receipt.request.target_device_ids.is_empty()
        && claim
            .device_id
            .as_ref()
            .is_none_or(|device_id| !receipt.request.target_device_ids.contains(device_id))
    {
        return Err("KeyPackage claim did not satisfy the exact target device selector".to_owned());
    }
    match (
        &receipt.request.target_agent_id,
        &receipt.request.target_agent_verification_method,
        &receipt.request.target_agent_key_authorize_event_id,
    ) {
        (None, None, None) => {}
        (Some(agent_id), Some(method), Some(authorize_event_id))
            if claim.agent_id.as_ref() == Some(agent_id)
                && claim.agent_verification_method.as_ref() == Some(method)
                && claim.agent_key_authorize_event_id.as_ref() == Some(authorize_event_id) => {}
        _ => {
            return Err(
                "KeyPackage claim did not satisfy the exact Native Agent selector".to_owned(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn welcome_intent_step(inputs: WelcomePayloadInputs) -> WelcomeIntentStep {
    Box::new(move |commit_event_id| {
        let payload = build_mls_welcome_payload(
            &inputs.realm_id,
            &inputs.actor_id,
            &inputs.device_id,
            &inputs.requester_device_authorize_event_id,
            &inputs.claim,
            &inputs.keypackage_id,
            &inputs.welcome_envelope,
            commit_event_id,
            inputs.governance_binding,
            &inputs.claim_nonce,
            &inputs.claim_receipt,
        )?;
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
    sender_device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    _key_package_id: &str,
    welcome: &arkret_sdk::MlsWelcomeEnvelope,
    commit_event_id: &arkret_sdk::EventId,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<arkret_sdk::MlsWelcomePayload, String> {
    let intended_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid MLS Welcome Realm id: {err:?}"))?;
    let requester_did = crate::mls_api_helpers::principal_core_id(actor_id)
        .map_err(|err| format!("invalid MLS Welcome requester principal core id: {err:?}"))?;
    let sender_device_id = arkret_sdk::DeviceId::new(sender_device_id.trim().to_owned())
        .map_err(|err| format!("invalid MLS Welcome sender device id: {err:?}"))?;
    let envelope = arkret_sdk::UnsignedMlsWelcomeClaimEnvelope::new(
        arkret_sdk::MlsWelcomeClaimEnvelopeSigningInput {
            keypackage_ref: claim.keypackage_ref.clone(),
            keypackage_digest: claim.keypackage_digest.clone(),
            intended_realm_id,
            claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
                .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
            requester_actor_id: requester_did,
            trust_binding: arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
                requester_device_id: sender_device_id.clone(),
                requester_device_authorize_event_id: requester_device_authorize_event_id.clone(),
            },
            nonce: arkret_sdk::NonEmptyString::new(claim_nonce.trim())
                .map_err(|err| format!("invalid MLS Welcome claim nonce: {err}"))?,
            welcome_digest: welcome.welcome_hash.clone(),
            created_at: crate::clock::now_utc_canonical(),
        },
    );
    let envelope = sign_welcome_claim_envelope(actor_id, sender_device_id.as_str(), envelope)?;
    let claim_trust_binding = match (
        claim.device_authorize_event_id.as_ref(),
        claim.agent_key_authorize_event_id.as_ref(),
    ) {
        (Some(event_id), None) => arkret_sdk::MlsClaimTrustBinding::DeviceAuthorizeEventId(
            arkret_sdk::NonEmptyString::new(event_id.as_str())
                .map_err(|err| format!("invalid device authorization event id: {err}"))?,
        ),
        (None, Some(event_id)) => arkret_sdk::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(
            arkret_sdk::NonEmptyString::new(event_id.as_str())
                .map_err(|err| format!("invalid Agent key authorization event id: {err}"))?,
        ),
        _ => return Err("MLS KeyPackage claim must contain exactly one trust binding".to_owned()),
    };
    let claim_ref = arkret_sdk::MlsWelcomePayloadClaimRef {
        claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
            .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest: claim.keypackage_digest.clone(),
        capabilities_digest: claim.capabilities_digest.clone(),
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
            arkret_sdk::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id: agent_id.clone(),
                recipient_agent_verification_method: method.clone(),
                agent_key_authorize_event_id: authorize_event_id.clone(),
            }
        }
        _ => return Err("MLS KeyPackage claim has an invalid recipient branch".to_owned()),
    };
    let expected_endpoint = match &recipient {
        arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => arkret_sdk::MlsEndpointIdentity::human_device(
            claim.principal_id.clone(),
            recipient_device_id.clone(),
        ),
        arkret_sdk::MlsWelcomeRecipient::NativeAgent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
            recipient_agent_id.clone(),
            recipient_agent_verification_method.clone(),
            agent_key_authorize_event_id.clone(),
        )
        .map_err(|error| format!("invalid Native Agent Welcome endpoint: {error}"))?,
    };
    if welcome.recipient != expected_endpoint {
        return Err(
            "MLS Welcome recipient differs from the admitted KeyPackage endpoint".to_owned(),
        );
    }
    let payload = arkret_sdk::MlsWelcomePayload {
        mls_group_id: arkret_sdk::MlsGroupId::new(welcome.group_id.clone())
            .map_err(|err| format!("invalid MLS Welcome group id: {err}"))?,
        epoch: welcome.epoch,
        recipient_principal_id: claim.principal_id.clone(),
        recipient,
        sender_device_id: Some(sender_device_id),
        keypackage_ref: claim.keypackage_ref.clone(),
        keypackage_digest: claim.keypackage_digest.clone(),
        claim_id: arkret_sdk::NonEmptyString::new(claim.claim_id.clone())
            .map_err(|err| format!("invalid MLS Welcome claim id: {err}"))?,
        claim_ref,
        claim_envelope: envelope,
        claim_receipt: claim_receipt.clone(),
        carrier: arkret_sdk::MlsWelcomeCarrier::new(
            None,
            None,
            Some(
                arkret_sdk::NonEmptyString::new(welcome.welcome.clone())
                    .map_err(|err| format!("invalid MLS Welcome ciphertext: {err}"))?,
            ),
        )
        .map_err(str::to_owned)?,
        commit_ref: Some(commit_event_id.clone()),
        governance_binding,
        expires_at,
    };
    Ok(payload)
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
    // The Welcome transcript is requester-principal scoped. Its device
    // signature therefore uses the same accepted principal/device method as
    // the Event proof, while the underlying local key remains unchanged.
    // Advertising the signer's local did:key method here prevents a remote
    // Principal Server from matching the signature to requester_device_id.
    let kid = arkret_sdk::NonEmptyString::new(format!("{actor_id}#{sender_device_id}"))
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
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime { .. }
            | arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                panic!("test fixture requires a human-device record")
            }
        };
        arkret_sdk::KeyPackageClaimRecord {
            claim_id: "keypackage-test:Y2xhaW0tbm9uY2U".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            principal_id: principal_id.clone(),
            device_id: Some(device_id),
            agent_id: None,
            agent_verification_method: None,
            keypackage: record.keypackage.clone(),
            capabilities: record.capabilities.clone(),
            capabilities_digest: record.keypackage_ref.clone(),
            device_authorize_event_id: Some(
                arkret_sdk::EventId::new(device_authorize_event_id.to_owned()).unwrap(),
            ),
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
            device_signature: arkret_sdk::KeyOperationSignature {
                kid: arkret_sdk::NonEmptyString::new(format!("{}#device", principal_id.as_str()))
                    .unwrap(),
                signature_algorithm: Some(arkret_sdk::NonEmptyString::new("Ed25519").unwrap()),
                sig: arkret_sdk::Base64UrlString::new("c2ln").unwrap(),
            },
            revocation_status: None,
            last_resort: None,
        }
    }

    fn self_claim_receipt(
        claim: &arkret_sdk::KeyPackageClaimRecord,
        realm_id: &str,
        requester: &str,
        claim_nonce: &str,
    ) -> arkret_sdk::PeerKeyPackageClaimReceipt {
        let request = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: arkret_sdk::Base64UrlString::new(claim_nonce.to_owned()).unwrap(),
            target_principal_id: claim.principal_id.clone(),
            intended_realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            requester: crate::mls_api_helpers::principal_core_id(requester).unwrap(),
            mls_group_id: arkret_sdk::NonEmptyString::new(
                crate::mls::runtime::mls_group_id_for_realm(realm_id)
                    .expect("test Realm scope must derive a canonical MLS group id"),
            )
            .unwrap(),
            claim_purpose: arkret_sdk::PeerKeyPackageClaimPurpose::RealmMembership,
            required_capabilities: claim
                .capabilities
                .iter()
                .map(|value| arkret_sdk::NonEmptyString::new(value).unwrap())
                .collect(),
            claim_nonce: arkret_sdk::Base64UrlString::new(claim_nonce.to_owned()).unwrap(),
            expires_at: claim.expires_at,
            target_device_ids: claim.device_id.clone().into_iter().collect(),
            target_keypackage_ref: None,
            target_agent_id: None,
            target_agent_verification_method: None,
            target_agent_key_authorize_event_id: None,
            minimal_metadata_allowed: Some(true),
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
            source_service_id: authority.clone(),
            destination_service_id: authority,
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

    fn add_proposal_fixture(
        realm_id: &str,
    ) -> (
        arkret_sdk::MlsProposalEnvelope,
        arkret_sdk::MlsGovernanceBindingPayload,
    ) {
        let group_id = crate::mls::runtime::mls_group_id_for_realm(realm_id).unwrap();
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
    fn human_and_native_agent_adds_bind_the_exact_authorization_incarnation() {
        let realm = "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
        let bob = arkret_sdk::ArkretMlsIdentity::new_basic(
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

        let human = build_add_proposal_event(
            realm,
            None,
            "did:web:alice.example",
            &claim,
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
        assert_eq!(human.target_device_id, claim.device_id);

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
        let native = build_add_proposal_event(
            realm,
            None,
            "did:web:alice.example",
            &claim,
            &proposal,
            incarnation.clone(),
            binding,
        )
        .unwrap()
        .typed_payload::<arkret_wire::event_spec::MlsProposal>()
        .unwrap();
        assert_eq!(native.target_authorization_incarnation, Some(incarnation));
        assert_eq!(native.target_principal_id, Some(claim.principal_id));
        assert_eq!(native.target_device_id, None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn welcome_device_signature_uses_active_device_signer() {
        let active_signer = std::sync::Arc::new(crate::event_signer::build_ed25519_signer(
            [7u8; 32],
            "did:key:zActiveSigner",
        ));
        let _signer_guard =
            crate::event_signer::ActiveSignerTestGuard::replace(Some(active_signer));
        let actor = "did:web:alice.example";
        let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
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
                requester_actor_id: arkret_sdk::DidCoreId::new(
                    "ak:did_core:web:alice.example".to_owned(),
                )
                .unwrap(),
                trust_binding: arkret_sdk::MlsRequesterTrustBinding::RequesterDevice {
                    requester_device_id: arkret_sdk::DeviceId::new(device).unwrap(),
                    requester_device_authorize_event_id: arkret_sdk::EventId::new(
                        "ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc",
                    )
                    .unwrap(),
                },
                nonce: arkret_sdk::NonEmptyString::new("nonce").unwrap(),
                welcome_digest: arkret_sdk::Hash::new(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                created_at: crate::clock::now_utc(),
            },
        );

        let envelope = sign_welcome_claim_envelope(actor, device, envelope).unwrap();

        assert_eq!(
            envelope
                .trust_binding
                .requester_device_id()
                .map(arkret_sdk::DeviceId::as_str),
            Some(device)
        );
        assert_eq!(envelope.signature.kid.as_str(), format!("{actor}#{device}"));
        assert!(!envelope.signature.sig.is_empty());
        assert!(!envelope.signature.sig.contains(['+', '/', '=']));
        assert!(
            URL_SAFE_NO_PAD
                .decode(envelope.signature.sig.as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn mismatched_claim_target_cannot_authorize_welcome() {
        let alice_state = isolated_store_for_tests("peer-self-claim-fail-closed");
        let secure = MemorySecureKeyStore::new();
        let realm = "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";
        let alice = "did:web:alice.example";
        let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
        let bob = "did:web:bob.example";
        let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b1";
        let bob_identity = arkret_sdk::ArkretMlsIdentity::new_basic(
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

        let claim_nonce = "Y2xhaW0tbm9uY2UtMDEyMzQ1Njc4OQ";
        let mut claim_receipt = self_claim_receipt(&claim, realm, alice, claim_nonce);
        claim_receipt.request.target_principal_id =
            crate::mls_api_helpers::principal_core_id(alice).unwrap();
        let authority = arkret_sdk::PrincipalAuthorityKey::new(
            crate::mls_api_helpers::principal_core_id(alice).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        let alice_device = arkret_sdk::DeviceId::new(alice_device.to_owned()).unwrap();
        let error = build_realm_mls_admission_events_from_claim(
            &alice_state,
            &secure,
            realm,
            &authority,
            alice,
            &alice_device,
            &requester_device_authorize_event_id,
            &claim,
            claim_nonce,
            &claim_receipt,
        )
        .err()
        .expect("remote claim must fail before MLS state mutation");

        assert!(
            error.contains("does not match the exact requester"),
            "{error}"
        );
        assert!(alice_state.mls_snapshot_for(realm).is_none());
    }
}
