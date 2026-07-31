//! Fresh-device recovery UI safety boundaries.
//!
//! Network coordination is owned by Garth's durable transaction engine. This
//! module owns only secret lifetime and the evidence required before the UI may
//! call a recovered device ready.

use arkret_crypto::DeviceTrustBinding;
use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceCrossSigningBinding, DeviceOrPrincipalRef,
};
use arkret_models_crypto::{
    ClientStepAttestationArtifact, RecoveryBackupClassUnlocked, RecoveryIdentityModel,
    RecoveryIdentityModel as ReceiptIdentityModel,
    RecoveryModelGenerationRef as ReceiptModelGenerationRef, RecoveryProofSummary,
    RecoveryPublicationAction, RecoveryReceipt, RecoveryReceiptAuthData, RecoveryReceiptOutcome,
    RecoverySessionState, RecoveryWelcomeRealmSummary, TypedClientStepAttestation,
    TypedSecurityTransactionContinueRequest,
};
#[cfg(feature = "joint-test-api")]
use arkret_wire::RecoveryAuthorityTicket;
use arkret_wire::security_transaction::PreparedEventSubmissionBatch;
use arkret_wire::{
    Audience, AuthorizationLease, AuthorizationLeaseId, BackupObjectRef, BackupRotationBinding,
    BackupRotationKind, BackupRotationPlan, BackupSeriesId, CLIENT_STEP_ATTESTATION_SIGNED_FIELDS,
    CanonicalPublicMaterial, ClientStepAttestationAuthData, ControlProposalDecisionPolicy,
    ControlProposalReceipt, DeviceId, Did, EnrollmentAuthorityRecoveryPlan, Event, EventId,
    EventInitialSubmission, EventsSubmitBatchRequestBody, GrantId, Hash, NonEmptyString,
    PayloadProof, PolicyId, PreparedEventUnit, PromoteRecoverySessionGrantOutcome,
    PromoteRecoverySessionGrantRequest, ReceiptId, RecoveryAuthorityHolderProof,
    RecoveryAuthorityTicketId, RecoveryBinding, RecoveryPreparedPlan,
    RecoveryTransactionCreateRequest, RiskTier, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionBinding, SecurityTransactionCreateRequest,
    SecurityTransactionPreparedPlan, SecurityTransactionState, SecurityTransactionStep,
    TransactionId, TypedTrustDomainId, proof_kind,
};
use chrono::{DateTime, Utc};
use garth::{SecurityTransactionEngine, SecurityTransactionStore, SecurityTransactionTransport};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Default)]
pub struct RecoveryWordsInput {
    words: Zeroizing<String>,
}

impl RecoveryWordsInput {
    pub fn replace(&mut self, value: impl Into<String>) {
        self.words.zeroize();
        self.words = Zeroizing::new(value.into());
    }

    pub fn normalized(&self) -> Option<Zeroizing<String>> {
        crate::recovery_crypto::normalize_recovery_key_input(self.words.as_str())
            .map(Zeroizing::new)
    }

    pub fn clear(&mut self) {
        self.words.zeroize();
        self.words.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn as_str(&self) -> &str {
        self.words.as_str()
    }
}

pub struct RecoveredCrossSigningAuthority {
    pub signer: crate::event_signer::InksonEventSigner,
    pub staged_secret: Zeroizing<Vec<u8>>,
}

pub async fn recover_cross_signing_publication_authority(
    api: &crate::transport::TransportClient,
    session: &RecoverySessionState,
    recovery_words: &str,
) -> anyhow::Result<RecoveredCrossSigningAuthority> {
    session.validate()?;
    if session.state != arkret_models_crypto::SessionState::Verified
        || session.identity_model != RecoveryIdentityModel::CrossSigning
    {
        anyhow::bail!("SSK recovery requires a verified cross-signing session");
    }
    let generation = session
        .ssk_generation
        .filter(|generation| *generation > 0)
        .ok_or_else(|| anyhow::anyhow!("cross-signing session omitted SSK generation"))?;
    let material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_words,
        "",
        0,
    )?;
    let list = serde_json::to_value(
        api.list_key_backups_by_series(None, Some("secret_storage"))
            .await?,
    )?;
    let matches = list
        .get("backups")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| {
            backup
                .get("encryption")
                .and_then(|value| value.get("recipient_method"))
                .and_then(serde_json::Value::as_str)
                == Some("recovery_public_key")
                && backup
                    .get("contents")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|item| {
                        item.get("item_kind").and_then(serde_json::Value::as_str)
                            == Some("self_signing_key")
                            && item
                                .get("secret_version")
                                .and_then(serde_json::Value::as_u64)
                                == Some(generation)
                    })
        })
        .cloned()
        .collect::<Vec<_>>();
    let [metadata] = matches.as_slice() else {
        anyhow::bail!(
            "expected exactly one recovery-directed SSK backup for generation {generation}, found {}",
            matches.len()
        );
    };
    let unlocked =
        crate::key_backup::fetch_key_backup_for_verified_recovery_session(api, metadata, session)
            .await?;
    let recovered = crate::recovery_strand::open_recovery_directed_ssk_backup(
        &unlocked,
        &material.backup_hpke_derived_private_key,
        session.principal_id.as_str(),
        generation,
    )?;
    if recovered.generation != generation {
        anyhow::bail!("recovered SSK generation differs from the session snapshot");
    }
    let ssk_seed = recovered.signing_key.to_bytes();
    let mut staged_secret = Zeroizing::new(Vec::with_capacity(65));
    staged_secret.push(1);
    staged_secret.extend_from_slice(&material.backup_hpke_derived_private_key);
    staged_secret.extend_from_slice(&ssk_seed);
    Ok(RecoveredCrossSigningAuthority {
        signer: crate::event_signer::build_ed25519_signer_with_verification_method(
            ssk_seed,
            session.principal_id.as_str(),
            recovered.kid,
        ),
        staged_secret,
    })
}

pub fn build_cross_signing_recovery_events(
    session: &RecoverySessionState,
    frontier: &arkret_models_collaboration::event_sync::RealmActorFrontierView,
    replacement_device_signer: &crate::event_signer::InksonEventSigner,
    replacement_device_hpke_public_key: &[u8; 32],
    recovered_ssk_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<(Event, Event)> {
    session.validate()?;
    if session.state != arkret_models_crypto::SessionState::Verified
        || session.identity_model != RecoveryIdentityModel::CrossSigning
    {
        anyhow::bail!("cross-signing recovery Events require a verified A-model session");
    }
    if frontier.actor_id != session.principal_id
        || frontier.realm_id != *session.publication_authority_context.scope_ref.realm_id()
    {
        anyhow::bail!("actor frontier differs from the recovery publication scope");
    }
    let generation = session
        .ssk_generation
        .filter(|generation| *generation > 0)
        .ok_or_else(|| anyhow::anyhow!("cross-signing session omitted SSK generation"))?;
    let device_id = replacement_device_signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("replacement signer is not bound to a device id"))?;
    if device_id != session.requesting_device_id.as_str() {
        anyhow::bail!("replacement signer device differs from the recovery session");
    }
    let device_public_key = replacement_device_signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement signer does not expose an Ed25519 key"))?;
    let mut hpke_multikey = vec![0xec, 0x01];
    hpke_multikey.extend_from_slice(replacement_device_hpke_public_key);
    let hpke_key = arkret_sdk::encode_multibase_base58btc(hpke_multikey);
    let algorithms = vec![
        "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
        "ak.mls.v1".to_owned(),
    ];
    let binding_input = DeviceTrustBinding::canonical_input(
        &session.principal_id,
        &session.requesting_device_id,
        &device_public_key,
        &hpke_key,
        &algorithms,
        generation,
    )?;
    let cross_signing_binding = DeviceCrossSigningBinding {
        verification_method: arkret_sdk::DidUrl::new(
            recovered_ssk_signer.verification_method().to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        alg: NonEmptyString::new("EdDSA".to_owned()).map_err(anyhow::Error::msg)?,
        ssk_generation: std::num::NonZeroU64::new(generation)
            .ok_or_else(|| anyhow::anyhow!("SSK generation must be positive"))?,
        signature: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            recovered_ssk_signer.sign_raw(&binding_input)?,
        ))
        .map_err(anyhow::Error::msg)?,
    };
    let now = crate::clock::now_utc();
    let mut payload = DeviceAuthorizePayload {
        principal_id: session.principal_id.clone(),
        device_id: session.requesting_device_id.clone(),
        device_public_key: NonEmptyString::new(device_public_key).map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new(hpke_key).map_err(anyhow::Error::msg)?,
        algorithms: algorithms
            .iter()
            .cloned()
            .map(NonEmptyString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::msg)?,
        device_key_algorithm: Some(
            NonEmptyString::new("EdDSA".to_owned()).map_err(anyhow::Error::msg)?,
        ),
        authorized_by: DeviceOrPrincipalRef::DeviceId(session.requesting_device_id.clone()),
        scopes: None,
        not_before: now,
        expires_at: None,
        device_signature: Some(SignatureMaterial::NonEmptyString(
            NonEmptyString::new("pending".to_owned()).map_err(anyhow::Error::msg)?,
        )),
        proof: None,
        cross_signing_binding: Some(cross_signing_binding),
        enrollment_authority_binding: None,
        recovery_session_id: Some(session.recovery_session_id.clone()),
    };
    payload.device_signature = Some(SignatureMaterial::NonEmptyString(
        NonEmptyString::new(arkret_sdk::base64url_encode(
            replacement_device_signer.sign_raw(&payload.device_possession_signature_input()?)?,
        ))
        .map_err(anyhow::Error::msg)?,
    ));
    let scope = session.publication_authority_context.scope_ref.clone();
    let mut hlc = arkret_sdk::HlcGenerator::new(
        frontier.realm_id.as_str(),
        session.requesting_device_id.as_str(),
        b"inkson-fresh-device-recovery",
    );
    let mut authorize = arkret_event_draft::build_device_authorize_event_at(
        scope.clone(),
        session.principal_id.clone(),
        frontier.next_actor_seq,
        hlc.generate(),
        payload,
        now,
    )?;
    authorize.prev_refs = frontier.frontier_event_ids.clone();
    authorize.seal_basis = session.accepted_seal_frontier.clone();

    let mut list_update = Event::new_at(
        "ak.device.list_update",
        scope,
        session.principal_id.clone(),
        frontier.next_actor_seq + 1,
        hlc.generate(),
        serde_json::json!({
            "principal_id": session.principal_id,
            "changed": [session.requesting_device_id],
            "updated_at": arkret_sdk::canonical::format_timestamp_canonical(now),
        }),
        now,
    )?;
    list_update.prev_refs = vec![authorize.event_id.clone()];
    list_update.seal_basis = session.accepted_seal_frontier.clone();

    let device_signer =
        replacement_device_signer.payload_signer_adapter_for_principal(&session.principal_id)?;
    let verification_method =
        replacement_device_signer.verification_method_for_principal(&session.principal_id)?;
    for event in [&mut authorize, &mut list_update] {
        arkret_sdk::signatures::sign_event(
            event,
            &device_signer,
            &verification_method,
            arkret_sdk::signatures::SignEventOptions::new().with_created_at(now),
        )?;
    }
    Ok((authorize, list_update))
}

pub struct PreparedCrossSigningRecovery {
    pub request: RecoveryTransactionCreateRequest,
    pub staged_secret: Zeroizing<Vec<u8>>,
}

pub async fn prepare_cross_signing_recovery_from_words(
    api: &crate::transport::TransportClient,
    secure_store: &dyn garth::SecureKeyStore,
    session: &RecoverySessionState,
    recovery_words: &str,
) -> anyhow::Result<PreparedCrossSigningRecovery> {
    let authority =
        recover_cross_signing_publication_authority(api, session, recovery_words).await?;
    let replacement_signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("fresh-device recovery requires an active device signer"))?;
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
    )?;
    let hpke_public_key: [u8; 32] = hpke_public_key.try_into().map_err(|key: Vec<u8>| {
        anyhow::anyhow!("device HPKE public key has {} bytes", key.len())
    })?;
    let control_realm = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(
        &session.principal_id,
    ))?;
    let frontier = api
        .http()
        .events_frontier(
            &arkret_models_collaboration::event_sync::EventsFrontierSelector::RealmActor {
                realm_id: control_realm,
                actor_id: session.principal_id.clone(),
            },
        )
        .await?;
    let frontier = match frontier.frontier {
        arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) => {
            frontier
        }
        _ => anyhow::bail!("principal actor frontier returned the wrong variant"),
    };
    let (authorize_event, list_event) = build_cross_signing_recovery_events(
        session,
        &frontier,
        replacement_signer.as_ref(),
        &hpke_public_key,
        &authority.signer,
    )?;
    let coordinator_service_id =
        Did::new(api.event_submitter()?.service_id().await?).map_err(anyhow::Error::msg)?;
    let request = prepare_cross_signing_recovery_transaction(
        session,
        coordinator_service_id,
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        ReceiptId::new(format!("ak:receipt:{}", crate::operation::uuid_v7()))?,
        session.expires_at,
        authorize_event,
        list_event,
        &authority.signer,
    )?;
    Ok(PreparedCrossSigningRecovery {
        request,
        staged_secret: authority.staged_secret,
    })
}

impl Drop for RecoveryWordsInput {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

pub fn sign_recovery_session_lease(
    session: &arkret_sdk::RecoverySessionState,
    event: &arkret_sdk::Event,
    issuer_verification_method: &str,
    issuer_key: &ed25519_dalek::SigningKey,
    issued_at: DateTime<Utc>,
) -> anyhow::Result<AuthorizationLease> {
    if session.state != arkret_sdk::SessionState::Verified {
        anyhow::bail!("recovery publication lease requires a verified session");
    }
    if issued_at < session.created_at || issued_at >= session.expires_at {
        anyhow::bail!("recovery publication lease timestamp is outside the verified session");
    }
    let context = &session.publication_authority_context;
    if context.scope_ref != event.scope_ref
        || !context.allowed_actions.iter().any(|action| {
            serde_json::to_value(action)
                .ok()
                .as_ref()
                .and_then(serde_json::Value::as_str)
                == Some(event.kind.as_str())
        })
    {
        anyhow::bail!("recovery publication context does not cover the Event");
    }
    let matching_rule = context
        .authority_set_policy
        .authorization_rules
        .iter()
        .find(|rule| {
            rule.allowed_actions
                .iter()
                .any(|action| action == event.kind.as_str())
                && rule.threshold == 1
                && rule
                    .issuers
                    .iter()
                    .any(|issuer| issuer.verification_method.as_str() == issuer_verification_method)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "recovery publication requires one snapshot rule issued by the recovered authority"
            )
        })?;
    let mut lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(format!(
            "ak:authorization_lease:{}",
            crate::operation::uuid_v7()
        ))?,
        basis_ref: context.basis_ref.clone(),
        actor_id: event.actor_id.clone(),
        device_id: session.requesting_device_id.clone(),
        scope_ref: context.scope_ref.clone(),
        action: event.kind.as_str().to_owned(),
        authorization_rule_id: matching_rule.rule_id.clone(),
        risk_tier: RiskTier::High,
        issued_at,
        expires_at: std::cmp::min(
            session.expires_at,
            issued_at + RiskTier::High.max_lease_ttl(),
        ),
        authority_set_ref: context.authority_set_ref.clone(),
        authority_set_policy: context.authority_set_policy.clone(),
        proofs: Vec::new(),
    };
    let mut proof = PayloadProof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        // §2.2: validate the caller-supplied issuer method into a typed DID URL.
        verification_method: arkret_sdk::DidUrl::new(issuer_verification_method.to_owned())
            .map_err(|error| {
                anyhow::anyhow!("recovery lease issuer verification method is invalid: {error}")
            })?,
        payload_digest: lease.lease_digest()?,
        created_at: issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::sign_eddsa_detached_jws(
        issuer_key,
        &lease.proof_binding_bytes(&proof)?,
    )?;
    lease.proofs.push(proof);
    lease.validate_structural()?;
    Ok(lease)
}

#[allow(clippy::too_many_arguments)]
pub fn cross_signing_recovery_create_request(
    session: &arkret_sdk::RecoverySessionState,
    proof_digest: Hash,
    coordinator_service_id: Did,
    transaction_id: TransactionId,
    terminal_receipt_id: ReceiptId,
    expires_at: DateTime<Utc>,
    authorize_submission: EventInitialSubmission,
    device_list_update_submission: EventInitialSubmission,
) -> anyhow::Result<RecoveryTransactionCreateRequest> {
    session.validate()?;
    if session.state != arkret_sdk::SessionState::Verified
        || session.identity_model != arkret_sdk::RecoveryIdentityModel::CrossSigning
    {
        anyhow::bail!("cross-signing recovery requires a verified A-model session");
    }
    let generation = session
        .ssk_generation
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow::anyhow!("cross-signing recovery session omits SSK generation"))?;
    if expires_at > session.expires_at {
        anyhow::bail!("recovery transaction cannot outlive its verified recovery session");
    }
    let snapshot_digest = Hash::new(arkret_sdk::canonical::canonical_sha256(session)?)?;
    let batch = PreparedEventSubmissionBatch::new(
        coordinator_service_id,
        EventsSubmitBatchRequestBody {
            events: vec![authorize_submission, device_list_update_submission],
        },
    )?;
    RecoveryTransactionCreateRequest::from_cross_signing_prepared(
        transaction_id,
        session.principal_id.clone(),
        expires_at,
        session.recovery_session_id.clone(),
        session.requesting_device_id.clone(),
        terminal_receipt_id,
        snapshot_digest,
        proof_digest,
        generation,
        generation,
        batch,
    )
    .map_err(anyhow::Error::from)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReadinessEvidence {
    pub transaction_completed_with_attestation: bool,
    pub holder_bound_grant_refreshed: bool,
    pub durable_device_authorized: bool,
    pub durable_control_generation_matches: bool,
    pub restore_report_committed: bool,
}

impl RecoveryReadinessEvidence {
    pub fn is_ready(&self) -> bool {
        self.transaction_completed_with_attestation
            && self.holder_bound_grant_refreshed
            && self.durable_device_authorized
            && self.durable_control_generation_matches
            && self.restore_report_committed
    }
}

/// Author one recovery-only publication lease from the immutable authority
/// snapshot embedded in a verified recovery session.
///
/// This performs no network operation. It is intentionally closed over the
/// three recovery actions and refuses to treat the replacement device signer
/// as an authority merely because it can sign the Event.
pub fn author_recovery_publication_submission(
    session: &RecoverySessionState,
    event: Event,
    action: RecoveryPublicationAction,
    authority_signer: &crate::event_signer::InksonEventSigner,
    replacement_device_id: DeviceId,
) -> anyhow::Result<EventInitialSubmission> {
    session.validate()?;
    if session.state != arkret_models_crypto::SessionState::Verified {
        anyhow::bail!("recovery publication requires a verified recovery session");
    }
    if session.requesting_device_id != replacement_device_id {
        anyhow::bail!("recovery publication replacement device differs from the session");
    }
    if event.actor_id != session.principal_id
        || event.scope_ref != session.publication_authority_context.scope_ref
    {
        anyhow::bail!("recovery publication Event actor or scope differs from the session");
    }
    let action_name = match action {
        RecoveryPublicationAction::DeviceAuthorize => "ak.device.authorize",
        RecoveryPublicationAction::DeviceListUpdate => "ak.device.list_update",
        RecoveryPublicationAction::DeviceReanchor => "ak.device.reanchor",
    };
    if event.kind.as_str() != action_name {
        anyhow::bail!("recovery publication action does not match the Event kind");
    }
    let expected_actions = match session.identity_model {
        RecoveryIdentityModel::CrossSigning => [
            RecoveryPublicationAction::DeviceAuthorize,
            RecoveryPublicationAction::DeviceListUpdate,
        ]
        .as_slice(),
        RecoveryIdentityModel::EnrollmentAuthority => {
            [RecoveryPublicationAction::DeviceReanchor].as_slice()
        }
    };
    if !expected_actions.contains(&action)
        || !session
            .publication_authority_context
            .allowed_actions
            .contains(&action)
    {
        anyhow::bail!("recovery publication action is not allowed by the session model");
    }

    let verification_method = authority_signer.verification_method();
    let rule = session
        .publication_authority_context
        .authority_set_policy
        .authorization_rules
        .iter()
        .find(|rule| {
            rule.allowed_actions
                .iter()
                .any(|value| value == action_name)
                && rule.threshold == 1
                && rule
                    .issuers
                    .iter()
                    .any(|issuer| issuer.verification_method.as_str() == verification_method)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "local recovery authority is not the sole accepted issuer for this action"
            )
        })?;
    let issued_at = crate::clock::now_utc();
    let risk_tier = RiskTier::High;
    let mut lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(format!(
            "ak:authorization_lease:{}",
            crate::operation::uuid_v7()
        ))?,
        basis_ref: session.publication_authority_context.basis_ref.clone(),
        actor_id: event.actor_id.clone(),
        device_id: replacement_device_id,
        scope_ref: event.scope_ref.clone(),
        action: action_name.to_owned(),
        authorization_rule_id: rule.rule_id.clone(),
        risk_tier,
        issued_at,
        expires_at: issued_at + risk_tier.max_lease_ttl(),
        authority_set_ref: session
            .publication_authority_context
            .authority_set_ref
            .clone(),
        authority_set_policy: session
            .publication_authority_context
            .authority_set_policy
            .clone(),
        proofs: Vec::new(),
    };
    let issuer_did = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .ok_or_else(|| {
            anyhow::anyhow!("recovery authority verification method is not a DID URL")
        })?;
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned()).map_err(
            |error| anyhow::anyhow!("recovery authority verification method is invalid: {error}"),
        )?,
        payload_digest: lease.lease_digest()?,
        created_at: issued_at,
        domain: None,
        audience: Some(Audience::Single(issuer_did.to_owned())),
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = lease.proof_binding_bytes(&proof)?;
    let signature = authority_signer.sign_raw(&binding)?;
    proof.jws = format!(
        "{}..{}",
        arkret_sdk::base64url_encode(br#"{"alg":"EdDSA"}"#),
        arkret_sdk::base64url_encode(signature)
    );
    lease.proofs.push(proof);
    lease.validate_structural()?;
    let control_proposal_receipt = event
        .seal_basis
        .as_ref()
        .map(|_| author_recovery_control_proposal_receipt(session, &event, authority_signer))
        .transpose()?;
    let submission = EventInitialSubmission {
        event,
        authorization_lease: lease,
        cba_proof_bundles: Vec::new(),
        control_proposal_receipt,
    };
    submission.validate_structural()?;
    Ok(submission)
}

/// Recovery publishes into the principal's own Control Realm, so it resolves
/// the same local authority route as every other Control Move and only supplies
/// the recovery-session signer.
fn author_recovery_control_proposal_receipt(
    session: &RecoverySessionState,
    event: &Event,
    authority_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<ControlProposalReceipt> {
    let policy = ControlProposalDecisionPolicy::default();
    let member = crate::authorization_lease::LocalPrincipalAuthority::self_principal_control_realm(
        &session.principal_id,
    )?
    .issue_member_receipt(event, authority_signer)?;
    ControlProposalReceipt::from_member_receipts(vec![member], policy).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_cross_signing_recovery_transaction(
    session: &RecoverySessionState,
    coordinator_service_id: Did,
    transaction_id: TransactionId,
    terminal_receipt_id: ReceiptId,
    expires_at: DateTime<Utc>,
    authorize_event: Event,
    device_list_update_event: Event,
    recovered_ssk_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<RecoveryTransactionCreateRequest> {
    if session.identity_model != RecoveryIdentityModel::CrossSigning {
        anyhow::bail!("cross-signing recovery cannot use an enrollment-authority session");
    }
    let generation = session
        .ssk_generation
        .filter(|generation| *generation > 0)
        .ok_or_else(|| anyhow::anyhow!("cross-signing recovery session omitted SSK generation"))?;
    let proof_digest = session
        .proof_summary
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?
        .proof_digest
        .clone();
    let authorize = author_recovery_publication_submission(
        session,
        authorize_event,
        RecoveryPublicationAction::DeviceAuthorize,
        recovered_ssk_signer,
        session.requesting_device_id.clone(),
    )?;
    let device_list_update = author_recovery_publication_submission(
        session,
        device_list_update_event,
        RecoveryPublicationAction::DeviceListUpdate,
        recovered_ssk_signer,
        session.requesting_device_id.clone(),
    )?;
    let request = EventsSubmitBatchRequestBody {
        events: vec![authorize, device_list_update],
    };
    let session_snapshot_digest = Hash::new(arkret_sdk::canonical::canonical_sha256(session)?)?;
    RecoveryTransactionCreateRequest::from_cross_signing_prepared(
        transaction_id,
        session.principal_id.clone(),
        expires_at,
        session.recovery_session_id.clone(),
        session.requesting_device_id.clone(),
        terminal_receipt_id,
        session_snapshot_digest,
        proof_digest,
        generation,
        generation,
        arkret_wire::security_transaction::PreparedEventSubmissionBatch::new(
            coordinator_service_id,
            request,
        )?,
    )
    .map_err(anyhow::Error::from)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_enrollment_authority_recovery_transaction(
    session: &RecoverySessionState,
    transaction_id: TransactionId,
    authority_ticket_id: RecoveryAuthorityTicketId,
    terminal_receipt_id: ReceiptId,
    expires_at: DateTime<Utc>,
    mut plan: EnrollmentAuthorityRecoveryPlan,
    recovery_authority_signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<RecoveryTransactionCreateRequest> {
    if session.identity_model != RecoveryIdentityModel::EnrollmentAuthority {
        anyhow::bail!("enrollment-authority recovery cannot use a cross-signing session");
    }
    let previous_generation = session
        .current_device_generation_ref
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("enrollment-authority session omitted current generation ref")
        })?
        .as_str();
    if plan.previous_model_generation_ref != previous_generation {
        anyhow::bail!("enrollment-authority plan changed the session generation fence");
    }
    let proof_digest = session
        .proof_summary
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?
        .proof_digest
        .clone();
    if plan.proof_digest != proof_digest
        || plan.authorization_preimage.recovery_session_id != session.recovery_session_id
        || plan.authorization_preimage.principal_id != session.principal_id
        || plan.authorization_preimage.replacement_device_id != session.requesting_device_id
    {
        anyhow::bail!("enrollment-authority plan differs from the verified session binding");
    }
    plan.recovery_session_snapshot_digest =
        Hash::new(arkret_sdk::canonical::canonical_sha256(session)?)?;
    plan.reanchor_event_submission = author_recovery_publication_submission(
        session,
        plan.reanchor_event_submission.event,
        RecoveryPublicationAction::DeviceReanchor,
        recovery_authority_signer,
        session.requesting_device_id.clone(),
    )?;
    plan.reanchor_event_submission_digest = Hash::new(arkret_sdk::canonical::canonical_sha256(
        &plan.reanchor_event_submission,
    )?)?;
    RecoveryTransactionCreateRequest::from_enrollment_authority_prepared(
        transaction_id,
        session.principal_id.clone(),
        expires_at,
        authority_ticket_id,
        terminal_receipt_id,
        plan,
    )
    .map_err(anyhow::Error::from)
}

/// Public-only result exposed to the cross-repository joint harness.
///
/// The recovery-key-derived HPKE private key deliberately stays inside the
/// normal Inkson preparation path and is dropped before this value returns.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub struct JointEnrollmentAuthorityRecoveryPreparation {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_sdk::ProofSummary,
    pub account_authority_endpoint: String,
    pub verified_session: RecoverySessionState,
}

/// Opaque public-only principal inception checkpoint used by cotest to put a
/// real B-model principal on the joint stack. The recovery words and derived
/// private material are not retained.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub struct JointPrincipalBootstrapPreparation {
    checkpoint: crate::state::PendingPrincipalRegistration,
}

#[cfg(feature = "joint-test-api")]
impl JointPrincipalBootstrapPreparation {
    pub fn principal_id(&self) -> &str {
        &self.checkpoint.did
    }

    pub fn version_id(&self) -> &str {
        &self.checkpoint.version_id
    }

    pub fn enrollment_authority_ref(&self) -> anyhow::Result<String> {
        let operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(self.checkpoint.did_operation.clone())?;
        operation
            .operation
            .get("state")
            .and_then(serde_json::Value::as_object)
            .and_then(|state| state.get("service"))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .find(|service| {
                service.get("type").and_then(serde_json::Value::as_str)
                    == Some("ArkretDeviceEnrollmentAuthority")
            })
            .and_then(|service| service.get("id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("principal inception omitted enrollment delegation"))
    }

    pub fn did_operation(&self) -> anyhow::Result<arkret_sdk::DidOperationSubmitRequestBody> {
        serde_json::from_value(self.checkpoint.did_operation.clone()).map_err(anyhow::Error::from)
    }
}

/// Prepare the same external-authority DID inception and public checkpoint as
/// onboarding, without retaining the caller's 24 words.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub fn prepare_joint_principal_bootstrap(
    principal_server_url: &str,
    gate_account_base: &str,
    account_handle: &str,
    enrollment_authority_did: &str,
    trust_domain: &str,
    device_id: &str,
    recovery_words: &str,
) -> anyhow::Result<JointPrincipalBootstrapPreparation> {
    let request_id = arkret_sdk::identifiers::new_prefixed_uuid7("ak:request:");
    let handoff = crate::state::PendingAccountHandoff {
        principal_server_url: principal_server_url.to_owned(),
        gate_account_base: gate_account_base.to_owned(),
        request_id,
        account_handle: account_handle.to_owned(),
        holder_jkt: String::new(),
        audience: String::new(),
        expires_at: crate::clock::now_utc() + chrono::Duration::hours(1),
        lease_id: Some(arkret_sdk::identifiers::new_prefixed_uuid7(
            "ak:identity_creation_lease:",
        )),
        lease_fence: Some(1),
        lease_expires_at: Some(crate::clock::now_utc() + chrono::Duration::hours(1)),
        reserved_identity: None,
        retry_after_ms: None,
        device_id: device_id.to_owned(),
        enrollment_authority_did: enrollment_authority_did.to_owned(),
        trust_domain: trust_domain.to_owned(),
    };
    Ok(JointPrincipalBootstrapPreparation {
        checkpoint: crate::identity::principal_registration::prepare_registration_checkpoint(
            &handoff,
            device_id,
            recovery_words,
        )?,
    })
}

/// Finish the exact founding PCR bootstrap after cotest has submitted the DID
/// inception and installed the Account Authority binding.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub async fn execute_joint_principal_bootstrap(
    prepared: &JointPrincipalBootstrapPreparation,
    recovery_words: &str,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
    account_client: &arkret_sdk::http_client::Client,
    principal_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    crate::identity::principal_registration::bootstrap_principal(
        &prepared.checkpoint,
        recovery_words,
        device_public_key,
        hpke_key,
        device_signer,
        account_client,
        principal_client,
    )
    .await
}

/// Establish the same signed recovery policy and encrypted DID-recovery
/// backup as the product setup flow on an already bootstrapped joint fixture.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub async fn establish_joint_recovery_policy_and_backup(
    principal_http: arkret_sdk::http_client::Client,
    principal_id: &str,
    device_id: &str,
    recovery_words: &str,
    device_signing_seed: [u8; 32],
    device_signer: std::sync::Arc<crate::event_signer::InksonEventSigner>,
) -> anyhow::Result<String> {
    crate::secure_key_store::set_active_device_seed_scope(Some(principal_id));
    crate::secure_key_store::store_signing_seed_scoped(
        crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        Some(principal_id),
        &device_signing_seed,
    )?;
    crate::event_signer::replace_active_signer(Some(device_signer));
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    let api = crate::transport::TransportClient::from_http(
        principal_http,
        crate::transport::RequestContext::new(""),
    );
    let did_recovery_backup_id =
        crate::recovery_strand::ensure_recovery_policy_and_did_recovery_backup(
            &api,
            principal_id,
            device_id,
            recovery_words,
        )
        .await?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    crate::mls::runtime::load_or_create_account_mls_secret(
        secure_store.as_ref(),
        principal_id,
        device_id,
    )?;
    crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
        &api,
        secure_store.as_ref(),
        principal_id,
        device_id,
        recovery_words,
    )
    .await?;
    Ok(did_recovery_backup_id)
}

/// Prepare the exact enrollment-authority recovery transaction used by the
/// product client while allowing cotest to drive each durable participant
/// boundary independently.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub async fn prepare_joint_enrollment_authority_recovery(
    principal_http: arkret_sdk::http_client::Client,
    principal_server_url: &str,
    session: &RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
    recovery_holder_jkt: &str,
) -> anyhow::Result<JointEnrollmentAuthorityRecoveryPreparation> {
    let api = crate::transport::TransportClient::from_http(
        principal_http,
        crate::transport::RequestContext::new(""),
    );
    let prepared = crate::mls::account_recovery::prepare_enrollment_authority_recovery(
        &api,
        principal_server_url,
        session,
        proof_outcome,
        recovery_words,
        recovery_holder_jkt,
    )
    .await?;
    Ok(JointEnrollmentAuthorityRecoveryPreparation {
        create_request: prepared.create_request,
        proof_summary: prepared.proof_summary,
        account_authority_endpoint: prepared.account_authority_endpoint,
        verified_session: prepared.verified_session,
    })
}

/// Open and verify a real recovery session from the 24 words, then prepare the
/// enrollment-authority transaction through the product orchestration path.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub async fn prepare_joint_enrollment_authority_recovery_from_words(
    principal_http: arkret_sdk::http_client::Client,
    principal_server_url: &str,
    principal_id: &str,
    replacement_device_id: &str,
    trust_domain: arkret_sdk::TypedTrustDomainId,
    recovery_words: &str,
    recovery_holder_jkt: &str,
) -> anyhow::Result<JointEnrollmentAuthorityRecoveryPreparation> {
    let api = crate::transport::TransportClient::from_http(
        principal_http.clone(),
        crate::transport::RequestContext::new(""),
    );
    let policy = crate::recovery_strand::fetch_active_recovery_policy(&api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("joint recovery policy is absent"))?;
    let session = api
        .create_recovery_session(&arkret_models_crypto::RecoverySessionCreateRequestBody {
            principal_id: arkret_sdk::Did::new(principal_id.to_owned())?,
            requesting_device_id: arkret_sdk::DeviceId::new(replacement_device_id.to_owned())?,
            trust_domain,
            expected_recovery_policy_ref: Some(arkret_models_crypto::RecoveryPolicyRef {
                policy_id: policy.policy_id.clone(),
                policy_version: policy.version,
            }),
        })
        .await?;
    let proof = crate::recovery_strand::build_recovery_unlock_proof_from_words(
        &session,
        &policy,
        recovery_words,
    )?;
    let proof_outcome = api
        .submit_recovery_proof(
            session.recovery_session_id.as_str(),
            &arkret_models_crypto::RecoverySessionProofSubmitRequestBody { proof },
        )
        .await?;
    prepare_joint_enrollment_authority_recovery(
        principal_http,
        principal_server_url,
        &session,
        &proof_outcome,
        recovery_words,
        recovery_holder_jkt,
    )
    .await
}

/// Build the holder-bound Account Authority participant request through the
/// same Inkson implementation used by the product recovery workflow.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub fn joint_recovery_device_authorization_request(
    transaction: &SecurityTransaction,
    ticket: RecoveryAuthorityTicket,
    account_authority_endpoint: &str,
    holder_seed_base64url: &str,
    holder_jkt: &str,
) -> anyhow::Result<arkret_wire::AuthorizeRecoveryDeviceRequest> {
    let holder = crate::identity::account_auth::grant_dpop::device_handle_from_seed(
        holder_seed_base64url,
        holder_jkt,
    )?;
    crate::mls::account_recovery::authorize_recovery_device_request(
        transaction,
        ticket,
        account_authority_endpoint,
        &holder,
    )
}

#[derive(Clone, Debug)]
pub struct SecurityRotationBackupDraft {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub new_backup_bodies: Vec<serde_json::Value>,
    pub active_series_submission: EventsSubmitBatchRequestBody,
    pub old_backups: Vec<BackupObjectRef>,
}

#[derive(Clone, Debug)]
pub struct SecurityRotationDraft {
    pub transaction_id: TransactionId,
    pub principal_id: Did,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoke_submission: EventsSubmitBatchRequestBody,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<SecurityRotationBackupDraft>,
}

impl SecurityRotationDraft {
    /// Close all public rotation material into the protocol's exact
    /// secret_storage + mls_history plan. Secret bytes are deliberately not
    /// accepted by this API.
    pub fn into_create_request(
        self,
        coordinator_service_id: Did,
    ) -> anyhow::Result<SecurityRotationTransactionCreateRequest> {
        let revoke_event_id = exactly_one_event_id(&self.revoke_submission, "revoke")?;
        let revoke_unit = PreparedEventUnit::new(
            coordinator_service_id.clone(),
            serde_json::to_value(&self.revoke_submission)?,
        )?;
        let mut prepared = Vec::with_capacity(self.backup_rotations.len());
        for draft in self.backup_rotations {
            let active_series_event_id =
                exactly_one_event_id(&draft.active_series_submission, "active-series")?;
            let mut new_backups = draft
                .new_backup_bodies
                .iter()
                .map(backup_object_ref)
                .collect::<anyhow::Result<Vec<_>>>()?;
            new_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            let mut old_backups = draft.old_backups;
            old_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            let binding = BackupRotationBinding {
                backup_kind: draft.backup_kind,
                previous_series_id: draft.previous_series_id,
                new_series_id: draft.new_series_id,
                new_backups,
                active_series_event_id,
                old_backups,
            };
            prepared.push(BackupRotationPlan {
                binding,
                encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                    serde_json::Value::Array(draft.new_backup_bodies),
                )?,
                active_series_unit: PreparedEventUnit::new(
                    coordinator_service_id.clone(),
                    serde_json::to_value(draft.active_series_submission)?,
                )?,
            });
        }
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            self.transaction_id,
            self.principal_id,
            self.expires_at,
            revoke_event_id,
            revoke_unit,
            self.new_secret_commitment,
            prepared,
        )
        .map_err(anyhow::Error::from)
    }
}

fn exactly_one_event_id(
    submission: &EventsSubmitBatchRequestBody,
    label: &str,
) -> anyhow::Result<EventId> {
    let [event] = submission.events.as_slice() else {
        anyhow::bail!("{label} prepared unit must contain exactly one Event");
    };
    Ok(event.event.event_id.clone())
}

fn backup_object_ref(value: &serde_json::Value) -> anyhow::Result<BackupObjectRef> {
    let backup_id = value
        .get("backup_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("prepared backup body omits backup_id"))?;
    let ciphertext_digest = value
        .get("ciphertext_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("prepared backup body omits ciphertext_digest"))?;
    Ok(BackupObjectRef {
        backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())?,
        ciphertext_digest: Hash::new(ciphertext_digest.to_owned())?,
    })
}

pub struct RecoveryTerminalObservation {
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TypedTrustDomainId,
    pub proof_summary: RecoveryProofSummary,
    pub backup_classes_unlocked: Vec<RecoveryBackupClassUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

pub fn sign_terminal_receipt_continue(
    resource: &SecurityTransaction,
    observation: RecoveryTerminalObservation,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<TypedSecurityTransactionContinueRequest> {
    resource.validate_structural()?;
    if resource.state != SecurityTransactionState::AwaitingDeviceAttestation
        || resource.next_required_step != Some(SecurityTransactionStep::IssueTerminalReceipt)
    {
        anyhow::bail!(
            "terminal receipt may only be signed from authoritative awaiting_device_attestation state"
        );
    }
    let (binding, plan) = match (&resource.binding, &resource.prepared_plan) {
        (
            SecurityTransactionBinding::Recovery(binding),
            SecurityTransactionPreparedPlan::Recovery(plan),
        ) => (binding, plan),
        _ => anyhow::bail!("terminal receipt requires a recovery transaction"),
    };
    if observation.policy_version == 0
        || observation.proof_summary.proof_digest != *plan_proof_digest(plan)
    {
        anyhow::bail!("terminal observation does not match the accepted recovery proof");
    }

    let (
        new_device_id,
        authorization_event_id,
        device_list_update_event_id,
        reanchor_event_id,
        reanchor_batch_receipt_id,
        authority_ticket_id,
        did_entry_ref,
        previous_model_generation_ref,
        result_model_generation_ref,
    ) = match (binding, plan) {
        (RecoveryBinding::CrossSigning(binding), RecoveryPreparedPlan::CrossSigning(plan)) => (
            binding.replacement_device_id.clone(),
            binding.authorize_event_id.clone(),
            Some(binding.device_list_update_event_id.clone()),
            None,
            None,
            None,
            None,
            ReceiptModelGenerationRef::CrossSigning(
                std::num::NonZeroU64::new(plan.previous_model_generation_ref)
                    .ok_or_else(|| anyhow::anyhow!("previous SSK generation must be positive"))?,
            ),
            ReceiptModelGenerationRef::CrossSigning(
                std::num::NonZeroU64::new(plan.result_model_generation_ref)
                    .ok_or_else(|| anyhow::anyhow!("result SSK generation must be positive"))?,
            ),
        ),
        (
            RecoveryBinding::EnrollmentAuthority(binding),
            RecoveryPreparedPlan::EnrollmentAuthority(plan),
        ) => {
            let preimage = &plan.authorization_preimage;
            if observation.policy_id != preimage.policy_id
                || observation.policy_version != preimage.policy_version
                || observation.trust_domain != preimage.trust_domain
            {
                anyhow::bail!(
                    "terminal observation changed the enrollment-authority policy binding"
                );
            }
            let batch_receipt = resource
                .accepted_steps
                .iter()
                .find(|step| step.step == SecurityTransactionStep::SubmitReanchorUnit)
                .ok_or_else(|| anyhow::anyhow!("accepted re-anchor unit is missing"))?;
            (
                binding.replacement_device_id.clone(),
                binding.authorize_event_id.clone(),
                None,
                Some(binding.reanchor_event_id.clone()),
                Some(ReceiptId::new(batch_receipt.output_ref.clone())?),
                Some(binding.authority_ticket_id.clone()),
                Some(binding.did_entry_ref.clone()),
                ReceiptModelGenerationRef::EnrollmentAuthority(
                    NonEmptyString::new(plan.previous_model_generation_ref.clone())
                        .map_err(anyhow::Error::msg)?,
                ),
                ReceiptModelGenerationRef::EnrollmentAuthority(
                    NonEmptyString::new(plan.result_model_generation_ref.clone())
                        .map_err(anyhow::Error::msg)?,
                ),
            )
        }
        _ => anyhow::bail!("recovery binding and prepared plan models disagree"),
    };

    let mut signed_fields = vec![
        "schema",
        "receipt_id",
        "transaction_id",
        "transaction_request_digest",
        "prepared_plan_digest",
        "principal_id",
        "recovery_session_id",
        "policy_id",
        "policy_version",
        "trust_domain",
        "new_device_id",
        "identity_model",
        "previous_model_generation_ref",
        "result_model_generation_ref",
        "authorization_event_id",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    match binding {
        RecoveryBinding::CrossSigning(_) => {
            signed_fields.push("device_list_update_event_id".into())
        }
        RecoveryBinding::EnrollmentAuthority(_) => signed_fields.extend(
            [
                "reanchor_event_id",
                "reanchor_batch_receipt_id",
                "authority_ticket_id",
                "did_entry_ref",
            ]
            .into_iter()
            .map(str::to_owned),
        ),
    }
    signed_fields.extend(
        ["proof_summary", "backup_classes_unlocked", "welcome_count"]
            .into_iter()
            .map(str::to_owned),
    );
    if observation.welcome_realm_summary.is_some() {
        signed_fields.push("welcome_realm_summary".into());
    }
    signed_fields.extend(
        ["outcome", "started_at", "completed_at"]
            .into_iter()
            .map(str::to_owned),
    );
    let replacement_verification_method =
        signer.verification_method_for_principal(&resource.principal_id)?;

    let mut receipt = RecoveryReceipt {
        schema: "ak.schema.recovery_receipt.v1".to_owned(),
        receipt_id: binding.terminal_receipt_id().clone(),
        transaction_id: resource.transaction_id.clone(),
        transaction_request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        principal_id: resource.principal_id.clone(),
        recovery_session_id: binding.recovery_session_id().clone(),
        policy_id: observation.policy_id,
        policy_version: observation.policy_version,
        trust_domain: observation.trust_domain,
        new_device_id,
        identity_model: match binding {
            RecoveryBinding::CrossSigning(_) => ReceiptIdentityModel::CrossSigning,
            RecoveryBinding::EnrollmentAuthority(_) => ReceiptIdentityModel::EnrollmentAuthority,
        },
        previous_model_generation_ref,
        result_model_generation_ref,
        authorization_event_id,
        device_list_update_event_id,
        reanchor_event_id,
        reanchor_batch_receipt_id,
        authority_ticket_id,
        did_entry_ref,
        proof_summary: observation.proof_summary,
        backup_classes_unlocked: observation.backup_classes_unlocked,
        welcome_count: observation.welcome_count,
        welcome_realm_summary: observation.welcome_realm_summary,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: observation.started_at,
        completed_at: observation.completed_at,
        auth_data: RecoveryReceiptAuthData {
            verification_method: replacement_verification_method.clone(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: String::new(),
            signed_fields,
        },
        extra: Default::default(),
    };
    let receipt_signature = signer.sign_raw(&receipt.signature_transcript_bytes()?)?;
    receipt.auth_data.signature = arkret_sdk::base64url_encode(receipt_signature);
    receipt.validate()?;

    let artifact = ClientStepAttestationArtifact::RecoveryReceipt(receipt);
    let artifact_bytes = arkret_sdk::canonical::canonical_json_bytes(&artifact)?;
    let mut attestation = TypedClientStepAttestation {
        step: SecurityTransactionStep::IssueTerminalReceipt,
        output_ref: binding.terminal_receipt_id().as_str().to_owned(),
        transaction_id: resource.transaction_id.clone(),
        transaction_request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        attestation_digest: Hash::new(arkret_sdk::canonical::sha256_digest(&artifact_bytes))?,
        artifact,
        auth_data: ClientStepAttestationAuthData {
            verification_method: replacement_verification_method,
            alg: "EdDSA".to_owned(),
            signature: String::new(),
            signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        },
    };
    let outer_signature = signer.sign_raw(&attestation.signing_bytes()?)?;
    attestation.auth_data.signature = arkret_sdk::base64url_encode(outer_signature);
    attestation.validate_structural()?;

    Ok(TypedSecurityTransactionContinueRequest {
        request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        expected_next_step: SecurityTransactionStep::IssueTerminalReceipt,
        client_attestation: Some(attestation),
        participant_request: None,
    })
}

fn plan_proof_digest(plan: &RecoveryPreparedPlan) -> &Hash {
    match plan {
        RecoveryPreparedPlan::CrossSigning(plan) => &plan.proof_digest,
        RecoveryPreparedPlan::EnrollmentAuthority(plan) => &plan.proof_digest,
    }
}

/// Thin UI-facing facade over Garth's durable coordinator.
///
/// Callers author and sign protocol artifacts outside this type. Every
/// continuation, including the terminal receipt, is handed to Garth before
/// transport so a response-loss retry reuses the exact canonical bytes.
pub struct FreshDeviceRecovery<T, S> {
    engine: SecurityTransactionEngine<T, S>,
}

impl<T, S> FreshDeviceRecovery<T, S>
where
    T: SecurityTransactionTransport,
    S: SecurityTransactionStore,
{
    pub fn new(engine: SecurityTransactionEngine<T, S>) -> Self {
        Self { engine }
    }

    pub async fn create_or_resume(
        &self,
        request: RecoveryTransactionCreateRequest,
        encrypted_staged_material_ref: Option<String>,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .create_or_resume(
                &SecurityTransactionCreateRequest::Recovery(request),
                encrypted_staged_material_ref,
            )
            .await
    }

    /// GET is authoritative; the UI must render this result rather than
    /// advancing a local success flag.
    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn continue_with_signed_artifact(
        &self,
        transaction_id: &TransactionId,
        request: &TypedSecurityTransactionContinueRequest,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .continue_transaction(transaction_id, request)
            .await
    }

    pub async fn retry_byte_identical_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<SecurityTransaction>> {
        self.engine.retry_pending(transaction_id).await
    }

    pub async fn promote_holder_bound_grant(
        &self,
        transaction_id: &TransactionId,
        request: &PromoteRecoverySessionGrantRequest,
    ) -> garth::Result<PromoteRecoverySessionGrantOutcome> {
        self.engine
            .promote_recovery_session_grant(transaction_id, request)
            .await
    }

    pub fn build_holder_bound_promotion(
        &self,
        transaction_id: &TransactionId,
        old_grant_id: GrantId,
        account_authority_endpoint: &str,
        holder: &crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> anyhow::Result<PromoteRecoverySessionGrantRequest> {
        let endpoint = url::Url::parse(account_authority_endpoint)?;
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/_arkret/gate/account/recovery-session-grants/promote"
        {
            anyhow::bail!("recovery grant promotion requires the exact standard HTTPS endpoint");
        }
        let local = self
            .engine
            .local_state(transaction_id)?
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no durable local state"))?;
        let resource = local
            .last_observed_resource
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no authoritative resource"))?;
        if resource.state != SecurityTransactionState::Completed {
            anyhow::bail!("recovery grant promotion requires a completed transaction");
        }
        let terminal_result = resource
            .terminal_result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("completed recovery transaction omitted result"))?;
        let completion_attestation = terminal_result
            .completion_attestation
            .clone()
            .ok_or_else(|| anyhow::anyhow!("completed recovery transaction omitted attestation"))?;
        let terminal_continue = local.accepted_terminal_continue.as_ref().ok_or_else(|| {
            anyhow::anyhow!("completed recovery transaction omitted its durable terminal receipt")
        })?;
        let terminal_request: TypedSecurityTransactionContinueRequest = serde_json::from_value(
            arkret_sdk::canonical::parse_canonical_json(terminal_continue)?,
        )?;
        let receipt = match terminal_request
            .client_attestation
            .ok_or_else(|| anyhow::anyhow!("terminal continuation omitted client attestation"))?
            .artifact
        {
            ClientStepAttestationArtifact::RecoveryReceipt(receipt) => receipt,
            ClientStepAttestationArtifact::SecurityRotationLocalCommit(_) => {
                anyhow::bail!("recovery promotion cannot use a rotation local commit")
            }
        };
        let terminal_receipt = serde_json::to_value(receipt)?;
        let mut request = PromoteRecoverySessionGrantRequest {
            old_grant_id,
            transaction_id: transaction_id.clone(),
            transaction_request_digest: resource.request_digest.clone(),
            terminal_receipt,
            completion_attestation: completion_attestation.clone(),
            device_authorization_event_id: completion_attestation
                .device_authorization_event_id
                .clone(),
            result_model_generation_ref: completion_attestation.result_model_generation_ref.clone(),
            canonical_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            holder_proof: RecoveryAuthorityHolderProof {
                dpop_jkt: holder.jkt().to_owned(),
                proof_jwt: String::new(),
            },
        };
        request.canonical_request_digest = request.expected_canonical_request_digest()?;
        let jti = format!("urn:uuid:{}", crate::operation::uuid_v7());
        request.holder_proof.proof_jwt = holder.mint_recovery_authority_proof(
            endpoint.as_str(),
            request.canonical_request_digest.as_str(),
            &jti,
        )?;
        request.validate_structural()?;
        Ok(request)
    }

    pub async fn retry_byte_identical_promotion(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<PromoteRecoverySessionGrantOutcome>> {
        self.engine.retry_pending_promotion(transaction_id).await
    }

    pub fn install_promoted_holder_bound_grant(
        &self,
        store: &mut crate::state::LocalStateStore,
        outcome: &PromoteRecoverySessionGrantOutcome,
        principal_server_url: &str,
        holder: &crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> anyhow::Result<crate::state::PersistedSessionGrant> {
        crate::identity::session_refresh::persist_promoted_recovery_grant(
            store,
            outcome,
            principal_server_url,
            holder,
        )
    }
}

/// Device-revoke UI entrypoint for the fixed two-kind rotation transaction.
/// It intentionally accepts only the closed SDK request, so the former
/// single-secret upload/delete saga cannot be represented.
pub struct DeviceRevokeSecurityRotation<T, S> {
    engine: SecurityTransactionEngine<T, S>,
}

impl<T, S> DeviceRevokeSecurityRotation<T, S>
where
    T: SecurityTransactionTransport,
    S: SecurityTransactionStore,
{
    pub fn new(engine: SecurityTransactionEngine<T, S>) -> Self {
        Self { engine }
    }

    pub async fn create_or_resume(
        &self,
        request: SecurityRotationTransactionCreateRequest,
        encrypted_staged_material_ref: String,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .create_or_resume(
                &SecurityTransactionCreateRequest::SecurityRotation(request),
                Some(encrypted_staged_material_ref),
            )
            .await
    }

    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn continue_server_step(
        &self,
        transaction: &SecurityTransaction,
    ) -> garth::Result<SecurityTransaction> {
        let step = transaction.next_required_step.ok_or_else(|| {
            garth::Error::Protocol("security rotation has no next server step".to_owned())
        })?;
        if matches!(
            step,
            arkret_wire::SecurityTransactionStep::EraseOldMaterial
                | arkret_wire::SecurityTransactionStep::LocalCommit
        ) {
            return Err(garth::Error::Protocol(
                "erase and local commit require their typed dedicated operations".to_owned(),
            ));
        }
        self.engine
            .continue_transaction(
                &transaction.transaction_id,
                &TypedSecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_next_step: step,
                    client_attestation: None,
                    participant_request: None,
                },
            )
            .await
    }

    pub async fn continue_with_signed_local_commit(
        &self,
        transaction_id: &TransactionId,
        request: &TypedSecurityTransactionContinueRequest,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .continue_transaction(transaction_id, request)
            .await
    }

    pub async fn erase_old_series(
        &self,
        transaction_id: &TransactionId,
        request: &arkret_models_crypto::BackupSeriesEraseRequestBody,
    ) -> garth::Result<arkret_models_crypto::BackupSeriesEraseOutcome> {
        self.engine
            .erase_backup_series(transaction_id, request)
            .await
    }

    pub async fn retry_pending_erase(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<arkret_models_crypto::BackupSeriesEraseOutcome>> {
        self.engine.retry_pending_erase(transaction_id).await
    }

    pub async fn retry_byte_identical_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<SecurityTransaction>> {
        self.engine.retry_pending(transaction_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_requires_every_durable_evidence_source() {
        let complete = RecoveryReadinessEvidence {
            transaction_completed_with_attestation: true,
            holder_bound_grant_refreshed: true,
            durable_device_authorized: true,
            durable_control_generation_matches: true,
            restore_report_committed: true,
        };
        assert!(complete.is_ready());
        for missing in 0..5 {
            let mut evidence = complete.clone();
            match missing {
                0 => evidence.transaction_completed_with_attestation = false,
                1 => evidence.holder_bound_grant_refreshed = false,
                2 => evidence.durable_device_authorized = false,
                3 => evidence.durable_control_generation_matches = false,
                4 => evidence.restore_report_committed = false,
                _ => unreachable!(),
            }
            assert!(!evidence.is_ready());
        }
    }

    #[test]
    fn recovery_words_are_normalized_only_into_zeroizing_memory() {
        let phrase = crate::recovery_crypto::format_recovery_key(&[7u8; 32]);
        let mut input = RecoveryWordsInput::default();
        input.replace(format!("  {}  ", phrase.replace(' ', " \n ")));
        assert_eq!(
            input.normalized().as_deref().map(String::as_str),
            Some(phrase.as_str())
        );
        input.clear();
        assert!(input.is_empty());
    }
}
