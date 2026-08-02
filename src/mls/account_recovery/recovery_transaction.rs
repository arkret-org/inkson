use std::num::NonZeroU64;

use arkret_crypto::DeviceTrustBinding;
use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceCrossSigningBinding, DeviceListUpdatePayload,
    DeviceOrPrincipalRef,
};
use arkret_models_crypto::TypedSecurityTransactionContinueRequest;
use arkret_models_identity::artifacts_device_identity::{
    DeviceEnrollmentAuthorityBinding, DeviceEnrollmentAuthorityBindingKind,
};
use arkret_wire::{
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizeEventPublicationIntent, Base64UrlString, CanonicalPublicMaterial, DidUrl,
    EnrollmentAuthorityIdentityModel, EnrollmentAuthorityRecoveryPlan, Event, EventId, EventRef,
    Hash, Hlc, IssueAuthorityTicketStep, LeaseBasisRef, NonEmptyString, PreparedDidPublication,
    RECOVERY_ACCOUNT_AUTHORITY_SET_ID, ReceiptId, RecoveryAuthorityHolderProof,
    RecoveryAuthorityTicket, RecoveryAuthorityTicketId, RecoveryAuthorityTicketIssueRequest,
    RecoveryAuthorizationPreimage, RecoveryBinding, RecoveryPreparedPlan,
    RecoveryTransactionCreateRequest, ReplacementDevicePossessionProof, RiskTier, SchemaId,
    SecurityTransaction, SecurityTransactionBinding, SecurityTransactionCreateRequest,
    SecurityTransactionPreparedPlan, SecurityTransactionState, SecurityTransactionStep,
    TransactionId,
};
use dioxus::prelude::WritableExt as _;
use zeroize::Zeroizing;

pub(crate) struct PreparedCrossSigningRecovery {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_sdk::ProofSummary,
    pub recovery_private_key: Zeroizing<[u8; 32]>,
    pub verified_session: arkret_sdk::RecoverySessionState,
}

pub(crate) struct PreparedEnrollmentAuthorityRecovery {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_sdk::ProofSummary,
    pub recovery_private_key: Zeroizing<[u8; 32]>,
    pub account_authority_endpoint: String,
    pub verified_session: arkret_sdk::RecoverySessionState,
}

pub(crate) struct CompletedFreshDeviceRecovery {
    pub transaction_id: TransactionId,
    pub readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence,
    pub restore_report: super::RestoreReport,
}

fn reject_terminal_recovery_transaction(
    transaction: &SecurityTransaction,
    secure_store: &(dyn garth::SecureKeyStore + Send + Sync),
) -> anyhow::Result<()> {
    if transaction.state.is_terminal() && transaction.state != SecurityTransactionState::Completed {
        crate::security_transaction::clear_pending_fresh_device_recovery(secure_store)
            .map_err(anyhow::Error::from)?;
        anyhow::bail!(
            "recovery transaction {} ended in {:?}",
            transaction.transaction_id,
            transaction.state
        );
    }
    Ok(())
}

pub(crate) async fn prepare_cross_signing_recovery(
    api: &crate::transport::TransportClient,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<PreparedCrossSigningRecovery> {
    if proof_outcome.recovery_session_id != session.recovery_session_id
        || proof_outcome.state != arkret_sdk::SessionState::Verified
    {
        anyhow::bail!("recovery proof outcome did not verify the requested session");
    }
    let verified_session = api
        .recovery_session(session.recovery_session_id.as_str())
        .await?;
    verified_session.validate()?;
    if verified_session.state != arkret_sdk::SessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::CrossSigning
        || verified_session.recovery_session_id != session.recovery_session_id
        || verified_session.proof_summary != proof_outcome.proof_summary
    {
        anyhow::bail!("recovery session does not use the cross-signing model");
    }

    let generation = verified_session
        .ssk_generation
        .and_then(NonZeroU64::new)
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted SSK generation"))?;
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_words,
        "",
        0,
    )?;
    let backups = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        verified_session.principal_id.as_str(),
        verified_session.requesting_device_id.as_str(),
        &verified_session,
        &key_material,
    )
    .await?;
    let active_series = super::selection::active_series_id_for_backup_class(
        &backups,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    )
    .ok_or_else(|| anyhow::anyhow!("secret_storage active-series pointer is unavailable"))?;
    let active_backups = super::selection::iter_backup_bodies(&backups)
        .filter(|body| {
            body.get("series_id").and_then(serde_json::Value::as_str) == Some(active_series)
                && body.get("backup_kind").and_then(serde_json::Value::as_str)
                    == Some(crate::key_backup::BackupKind::SecretStorage.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected = active_backups
        .iter()
        .filter(|body| {
            body.get("contents")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|item| {
                    item.get("item_kind").and_then(serde_json::Value::as_str)
                        == Some("self_signing_key")
                        && item
                            .get("secret_version")
                            .and_then(serde_json::Value::as_u64)
                            == Some(generation.get())
                })
        })
        .max_by_key(|body| super::selection::backup_series_seq(body))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no recovery-directed self-signing key matches the verified session generation"
            )
        })?;
    super::series::verify_series_chain(selected, &active_backups)?;
    let recovered = crate::recovery_strand::open_recovery_directed_ssk_backup(
        selected,
        &key_material.backup_hpke_serialized_private_key,
        verified_session.principal_id.as_str(),
        generation.get(),
    )?;

    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
    let device_public_key = signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer has no Ed25519 public key"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store.as_ref(),
        verified_session.principal_id.as_str(),
        verified_session.requesting_device_id.as_str(),
    )?;
    let hpke_key = crate::identity::did_key::encode_x25519_multibase(&hpke_public_key);
    let algorithm_strings = crate::identity::device_enrollment::inkson_device_algorithms();
    let algorithms = algorithm_strings
        .iter()
        .map(|value| NonEmptyString::new(value.clone()).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let binding_input = DeviceTrustBinding::canonical_input(
        &verified_session.principal_id,
        &verified_session.requesting_device_id,
        &device_public_key,
        &hpke_key,
        &algorithm_strings,
        generation.get(),
    )?;
    let cross_signing_binding = DeviceCrossSigningBinding {
        verification_method: DidUrl::new(recovered.kid.clone()).map_err(anyhow::Error::msg)?,
        alg: NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?,
        ssk_generation: generation,
        signature: Base64UrlString::new(arkret_sdk::base64url_encode(
            ed25519_dalek::Signer::sign(&recovered.signing_key, &binding_input).to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?,
    };
    let now = crate::clock::now_utc_millis();
    let mut authorize_payload = DeviceAuthorizePayload {
        principal_id: verified_session.principal_id.clone(),
        device_id: verified_session.requesting_device_id.clone(),
        device_public_key: NonEmptyString::new(device_public_key).map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new(hpke_key).map_err(anyhow::Error::msg)?,
        algorithms,
        device_key_algorithm: Some(NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
        authorized_by: DeviceOrPrincipalRef::Did(verified_session.principal_id.clone()),
        scopes: None,
        not_before: now,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: Some(cross_signing_binding),
        enrollment_authority_binding: None,
        recovery_session_id: Some(verified_session.recovery_session_id.clone()),
    };
    authorize_payload.device_signature = Some(SignatureMaterial::NonEmptyString(
        NonEmptyString::new(arkret_sdk::base64url_encode(
            signer.sign_raw(&authorize_payload.device_possession_signature_input()?)?,
        ))
        .map_err(anyhow::Error::msg)?,
    ));

    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let placeholder_hlc = Hlc::new("000000000000-0000-00000000".to_owned())?;
    let mut authorize = Event::new_at(
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        scope_ref.clone(),
        verified_session.principal_id.clone(),
        1,
        placeholder_hlc.clone(),
        serde_json::to_value(authorize_payload)?,
        now,
    )?;
    apply_recovery_basis(
        &mut authorize,
        &verified_session.publication_authority_context.basis_ref,
    );
    let mut list_update = Event::new_at(
        arkret_wire::EventKind::DEVICE_LIST_UPDATE,
        scope_ref,
        verified_session.principal_id.clone(),
        1,
        placeholder_hlc,
        serde_json::to_value(DeviceListUpdatePayload {
            principal_id: verified_session.principal_id.clone(),
            changed: Some(vec![verified_session.requesting_device_id.clone()]),
            left: None,
            device_list_digest: None,
            stream_id: None,
            updated_at: Some(now),
        })?,
        now,
    )?;
    apply_recovery_basis(
        &mut list_update,
        &verified_session.publication_authority_context.basis_ref,
    );

    let submitter = api.event_submitter()?;
    let prepared = submitter
        .prepare_sdk_events_batch(vec![authorize, list_update])
        .await?;
    let [authorize, list_update] = prepared.as_slice() else {
        anyhow::bail!("cross-signing recovery did not prepare exactly two Events");
    };
    let issued_at = crate::clock::now_utc();
    let authorize_lease = crate::fresh_device_recovery::sign_recovery_session_lease(
        &verified_session,
        authorize,
        &recovered.kid,
        &recovered.signing_key,
        issued_at,
    )?;
    let list_lease = crate::fresh_device_recovery::sign_recovery_session_lease(
        &verified_session,
        list_update,
        &recovered.kid,
        &recovered.signing_key,
        issued_at,
    )?;
    crate::authorization_lease::install_lease(authorize_lease)?;
    crate::authorization_lease::install_lease(list_lease)?;
    let authorize_submission =
        crate::authorization_lease::delayed_initial_submission(&api.sdk_http_client()?, authorize)
            .await?;
    let list_submission = crate::authorization_lease::delayed_initial_submission(
        &api.sdk_http_client()?,
        list_update,
    )
    .await?;
    let coordinator_service_id = arkret_sdk::Did::new(submitter.service_id().await?)?;
    let proof_summary = verified_session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    let create_request = crate::fresh_device_recovery::cross_signing_recovery_create_request(
        &verified_session,
        proof_summary.proof_digest.clone(),
        coordinator_service_id,
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        ReceiptId::new(format!("ak:receipt:{}", crate::operation::uuid_v7()))?,
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        authorize_submission,
        list_submission,
    )?;
    Ok(PreparedCrossSigningRecovery {
        create_request,
        proof_summary,
        recovery_private_key: Zeroizing::new(key_material.backup_hpke_serialized_private_key),
        verified_session,
    })
}

pub(crate) async fn prepare_enrollment_authority_recovery(
    api: &crate::transport::TransportClient,
    principal_server_url: &str,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
    recovery_holder_jkt: &str,
) -> anyhow::Result<PreparedEnrollmentAuthorityRecovery> {
    if proof_outcome.recovery_session_id != session.recovery_session_id
        || proof_outcome.state != arkret_sdk::SessionState::Verified
    {
        anyhow::bail!("recovery proof outcome did not verify the requested session");
    }
    let verified_session = api
        .recovery_session(session.recovery_session_id.as_str())
        .await?;
    verified_session.validate()?;
    if verified_session.state != arkret_sdk::SessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::EnrollmentAuthority
        || verified_session.recovery_session_id != session.recovery_session_id
        || verified_session.proof_summary != proof_outcome.proof_summary
    {
        anyhow::bail!("recovery session does not use the enrollment-authority model");
    }
    let previous_generation = verified_session
        .current_device_generation_ref
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted device generation"))?
        .as_str()
        .to_owned();
    let current_root_generation = did_webvh_version_sequence(&previous_generation)?;
    let root_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            current_root_generation,
        )?;
    let backup_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;

    let http = api.sdk_http_client()?;
    let history = complete_identity_log(&http, verified_session.principal_id.as_str()).await?;
    let previous_entry = history
        .last()
        .ok_or_else(|| anyhow::anyhow!("principal DID history is empty"))?;
    if previous_entry
        .operation_body
        .get("versionId")
        .and_then(serde_json::Value::as_str)
        != Some(previous_generation.as_str())
        || verified_session.registry_head.as_ref() != Some(&previous_entry.head_event_digest)
    {
        anyhow::bail!("DID history head changed after the recovery session snapshot");
    }
    let document = http
        .identity_document(verified_session.principal_id.as_str(), None)
        .await?;
    if document.head_event_digest.as_ref() != verified_session.registry_head.as_ref() {
        anyhow::bail!("DID document head changed after the recovery session snapshot");
    }
    let document_state = serde_json::Value::Object(
        document
            .did_document
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>(),
    );
    let local_id = verified_session
        .principal_id
        .as_str()
        .rsplit(':')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("principal did:webvh has no local id"))?;
    let previous_entries = history
        .iter()
        .map(|entry| serde_json::Value::Object(entry.operation_body.clone()))
        .collect::<Vec<_>>();
    let rotation = arkret_sdk::webvh::prepare_principal_rotation(
        &arkret_sdk::webvh::PrincipalRotationInput {
            did: verified_session.principal_id.as_str(),
            local_id,
            previous_entries: &previous_entries,
            version_time: crate::clock::now_utc(),
            current_root_seed: &root_material.root_seed,
            next_root_public_key_multibase: &root_material.next_root_public_key_multikey,
            state: &document_state,
        },
    )?;
    if rotation.previous_version_id != previous_generation {
        anyhow::bail!("prepared DID rotation does not immediately follow the session snapshot");
    }
    let previous_entry_ref = format!(
        "{}?versionId={}",
        verified_session.principal_id, rotation.previous_version_id
    );
    let expected_entry_ref = format!(
        "{}?versionId={}",
        verified_session.principal_id, rotation.version_id
    );
    let did_entry_preimage = CanonicalPublicMaterial::canonical_json(rotation.log_entry.clone())?;

    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(principal_server_url).await?;
    if authority.principal_trust_domain != verified_session.trust_domain {
        anyhow::bail!("Account Authority trust domain changed after session creation");
    }
    let account_origin = url::Url::parse(&authority.gate_account_base)?
        .origin()
        .ascii_serialization();
    let account_description = crate::transport::TransportClient::unauthenticated(&account_origin)?
        .describe()
        .await?;
    let account_authority_id = account_description.service_id;
    let account_authority_endpoint = format!(
        "{}/recovery-device-authorizations",
        authority.gate_account_base.trim_end_matches('/')
    );
    let enrollment_authority_did = authority.enrollment_authority_did;
    let enrollment_verification_method = did_key_verification_method(&enrollment_authority_did)?;
    let authorization_ref = enrollment_delegation_ref(
        &document_state,
        &verified_session.principal_id,
        &enrollment_authority_did,
    )?;

    let submitter = api.event_submitter()?;
    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let actor_frontier = submitter
        .events_frontier_actor(
            verified_session.principal_id.as_str(),
            scope_ref.realm_id().as_str(),
        )
        .await?;
    actor_frontier.validate()?;
    let authorize_actor_seq = actor_frontier
        .next_actor_seq
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("recovery actor sequence exhausted"))?;
    let reanchor_event_id = EventId::new(format!("ak:event:{}", crate::operation::uuid_v7()))?;
    let authorize_event_id = EventId::new(format!("ak:event:{}", crate::operation::uuid_v7()))?;
    let not_before = crate::clock::now_utc_millis();
    let device_signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
    let device_public_key = device_signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer has no Ed25519 public key"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store.as_ref(),
        verified_session.principal_id.as_str(),
        verified_session.requesting_device_id.as_str(),
    )?;
    let hpke_key = crate::identity::did_key::encode_x25519_multibase(&hpke_public_key);
    let algorithm_strings = crate::identity::device_enrollment::inkson_device_algorithms();
    let algorithms = algorithm_strings
        .iter()
        .map(|value| NonEmptyString::new(value.clone()).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let enrollment_binding = DeviceEnrollmentAuthorityBinding {
        kind: DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
        authority_did: enrollment_authority_did.clone(),
        authorization_ref: NonEmptyString::new(authorization_ref.clone())
            .map_err(anyhow::Error::msg)?,
    };
    let mut authorize_payload = DeviceAuthorizePayload {
        principal_id: verified_session.principal_id.clone(),
        device_id: verified_session.requesting_device_id.clone(),
        device_public_key: NonEmptyString::new(device_public_key.clone())
            .map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new(hpke_key.clone()).map_err(anyhow::Error::msg)?,
        algorithms,
        device_key_algorithm: Some(NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
        authorized_by: DeviceOrPrincipalRef::Did(enrollment_authority_did.clone()),
        scopes: None,
        not_before,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(enrollment_binding),
        recovery_session_id: Some(verified_session.recovery_session_id.clone()),
    };
    let possession_input = authorize_payload.device_possession_signature_input()?;
    let possession_proof = ReplacementDevicePossessionProof {
        verification_method: device_signer
            .verification_method_for_principal(&verified_session.principal_id)?,
        alg: "EdDSA".to_owned(),
        transcript_digest: Hash::new(arkret_sdk::canonical::sha256_digest(&possession_input))?,
        signature: arkret_sdk::base64url_encode(device_signer.sign_raw(&possession_input)?),
    };
    authorize_payload.device_signature = Some(SignatureMaterial::Variant1(
        serde_json::to_value(&possession_proof)?
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("possession proof is not an object"))?
            .into_iter()
            .collect(),
    ));
    let reanchor_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let mut authorize_event = Event::new_with_id_at(
        authorize_event_id.clone(),
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        scope_ref.clone(),
        verified_session.principal_id.clone(),
        authorize_actor_seq,
        authorize_hlc,
        serde_json::to_value(authorize_payload)?,
        not_before,
    )?;
    authorize_event.prev_refs = vec![reanchor_event_id.clone()];
    authorize_event.executed_by = Some(enrollment_authority_did.clone());
    authorize_event.authorization_ref =
        Some(arkret_sdk::AuthorizationRef::new(authorization_ref).map_err(anyhow::Error::msg)?);
    let authorize_event_preimage =
        CanonicalPublicMaterial::canonical_json(serde_json::to_value(&authorize_event)?)?;

    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: RECOVERY_ACCOUNT_AUTHORITY_SET_ID.to_owned(),
        policy_kind: AuthoritySetPolicyKind::PrincipalControl,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::DidDocument,
            source_ref: previous_entry_ref.clone(),
            source_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(&document_state)?)?,
            generation_ref: rotation.previous_version_id.clone(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "account_authority".to_owned(),
            issuer_role: AuthoritySetIssuerRole::AccountEnrollmentAuthority,
            allowed_actions: vec!["ak.device.authorize".to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new(enrollment_verification_method.clone())
                    .map_err(anyhow::Error::msg)?,
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: authority_set_policy.authority_set_id.clone(),
        authority_set_digest: authority_set_policy.digest()?,
    };
    let publication_intent = AuthorizeEventPublicationIntent {
        event_id: authorize_event_id.clone(),
        event_preimage_digest: authorize_event_preimage.digest.clone(),
        actor_id: verified_session.principal_id.clone(),
        device_id: verified_session.requesting_device_id.clone(),
        scope_ref: scope_ref.clone(),
        action: "ak.device.authorize".to_owned(),
        authorization_rule_id: "account_authority".to_owned(),
        risk_tier: RiskTier::High,
        basis_ref: verified_session
            .publication_authority_context
            .basis_ref
            .clone(),
        authority_set_ref,
        authority_set_policy,
        cba_proof_bundles: Vec::new(),
    };

    let accepted_basis = verified_session
        .accepted_seal_frontier
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("verified recovery session has no accepted Seal frontier")
        })?;
    let digest_suite =
        crate::event_signer::digest_suite_from_trusted_hash(&accepted_basis.state_root)?;
    let reanchor_payload =
        arkret_models_collaboration::events_payloads::device_identity::DeviceReanchorPayload {
            principal_id: verified_session.principal_id.clone(),
            did_version_id: NonEmptyString::new(rotation.version_id.clone())
                .map_err(anyhow::Error::msg)?,
            previous_device_generation: NonEmptyString::new(previous_generation.clone())
                .map_err(anyhow::Error::msg)?,
            new_device_generation: NonEmptyString::new(rotation.version_id.clone())
                .map_err(anyhow::Error::msg)?,
            pre_fence_basis: verified_session.accepted_seal_frontier.clone(),
            replacement_authorize_event_id: authorize_event_id.clone(),
            replacement_authorize_digest: Hash::new(
                authorize_event.event_digest_with_digest_suite(digest_suite)?,
            )?,
        };
    let mut reanchor_event = Event::new_with_id_at(
        reanchor_event_id.clone(),
        arkret_wire::EventKind::DEVICE_REANCHOR,
        scope_ref,
        verified_session.principal_id.clone(),
        actor_frontier.next_actor_seq,
        reanchor_hlc,
        serde_json::to_value(reanchor_payload)?,
        not_before,
    )?;
    reanchor_event.prev_refs = actor_frontier.frontier_event_ids.clone();
    reanchor_event.refs.push(EventRef::new(
        rotation.version_id.clone(),
        "did_recovery_anchor",
    ));
    let root_did = arkret_sdk::Did::new(
        rotation
            .current_root_verification_method
            .split_once('#')
            .map_or(
                rotation.current_root_verification_method.as_str(),
                |(did, _)| did,
            )
            .to_owned(),
    )?;
    // §2.2: validate the stored root verification method into a typed DID URL
    // before it crosses into the signer / proof builder.
    let root_verification_method =
        arkret_sdk::DidUrl::new(rotation.current_root_verification_method.clone())
            .map_err(anyhow::Error::msg)?;
    let root_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        root_material.root_seed,
        root_did,
        root_verification_method.clone(),
    );
    arkret_signatures::sign_event_with_digest_suite(
        &mut reanchor_event,
        &root_signer,
        &root_verification_method,
        digest_suite,
        arkret_signatures::SignEventOptions::new().with_created_at(not_before),
    )?;
    let reanchor_lease = crate::fresh_device_recovery::sign_recovery_session_lease(
        &verified_session,
        &reanchor_event,
        &format!("{}#recovery-proof-0", verified_session.principal_id),
        &ed25519_dalek::SigningKey::from_bytes(&root_material.recovery_proof_seed),
        crate::clock::now_utc(),
    )?;
    crate::authorization_lease::install_lease(reanchor_lease)?;
    let reanchor_event_submission =
        crate::authorization_lease::initial_submission(&reanchor_event)?;

    let authorization_preimage = RecoveryAuthorizationPreimage {
        principal_id: verified_session.principal_id.clone(),
        replacement_device_id: verified_session.requesting_device_id.clone(),
        device_public_key,
        hpke_key,
        algorithms: algorithm_strings,
        recovery_session_id: verified_session.recovery_session_id.clone(),
        policy_id: verified_session.policy_id.clone(),
        policy_version: verified_session.policy_version,
        trust_domain: verified_session.trust_domain.clone(),
        account_authority_id,
        recovery_holder_jkt: recovery_holder_jkt.to_owned(),
        identity_model: EnrollmentAuthorityIdentityModel::EnrollmentAuthority,
        previous_model_generation_ref: previous_generation.clone(),
        result_model_generation_ref: rotation.version_id.clone(),
        registry_previous_head: previous_entry_ref.clone(),
        did_entry_ref: expected_entry_ref.clone(),
        did_entry_digest: did_entry_preimage.digest.clone(),
        did_entry_preimage: did_entry_preimage.clone(),
        reanchor_event_id,
        authorize_event_id,
        actor_seq: authorize_actor_seq,
        pre_fence_frontier_digest: actor_frontier.frontier_digest,
        not_before,
        authorize_event_preimage,
        authorize_event_publication_intent: publication_intent.clone(),
        possession_proof,
    };
    let registry_endpoint = http
        .base_url()
        .join("/_arkret/root/identity/submit-did-operation")?
        .to_string();
    let did_publication = PreparedDidPublication {
        registry_service_id: arkret_sdk::Did::new(submitter.service_id().await?)?,
        registry_endpoint,
        previous_entry_ref,
        expected_entry_ref,
        canonical_entry_base64url: did_entry_preimage.canonical_bytes_base64url.clone(),
        entry_digest: did_entry_preimage.digest.clone(),
    };
    let plan = EnrollmentAuthorityRecoveryPlan {
        identity_model: arkret_wire::RecoveryIdentityModel::EnrollmentAuthority,
        recovery_session_snapshot_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(
            &verified_session,
        )?)?,
        proof_digest: proof_outcome
            .proof_summary
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("verified proof outcome omitted summary"))?
            .proof_digest
            .clone(),
        previous_model_generation_ref: previous_generation,
        result_model_generation_ref: rotation.version_id,
        authorization_request_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(
            &authorization_preimage,
        )?)?,
        authorization_preimage,
        did_publication,
        reanchor_event_submission_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(
            &reanchor_event_submission,
        )?)?,
        reanchor_event_submission,
        authorize_event_publication_intent: publication_intent,
    };
    let create_request = RecoveryTransactionCreateRequest::from_enrollment_authority_prepared(
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        verified_session.principal_id.clone(),
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        RecoveryAuthorityTicketId::new(format!(
            "ak:recovery_authority_ticket:{}",
            crate::operation::uuid_v7()
        ))?,
        ReceiptId::new(format!("ak:receipt:{}", crate::operation::uuid_v7()))?,
        plan,
    )?;
    let proof_summary = verified_session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    Ok(PreparedEnrollmentAuthorityRecovery {
        create_request,
        proof_summary,
        recovery_private_key: Zeroizing::new(backup_material.backup_hpke_serialized_private_key),
        account_authority_endpoint,
        verified_session,
    })
}

fn did_webvh_version_sequence(version_id: &str) -> anyhow::Result<u64> {
    version_id
        .split_once('-')
        .and_then(|(sequence, _)| sequence.parse::<u64>().ok())
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| anyhow::anyhow!("DID generation is not a canonical did:webvh version id"))
}

fn did_key_verification_method(authority_did: &arkret_sdk::Did) -> anyhow::Result<String> {
    let multikey = authority_did
        .as_str()
        .strip_prefix("did:key:")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("enrollment authority is not a did:key identity"))?;
    Ok(format!("{authority_did}#{multikey}"))
}

fn enrollment_delegation_ref(
    state: &serde_json::Value,
    principal_id: &arkret_sdk::Did,
    authority_did: &arkret_sdk::Did,
) -> anyhow::Result<String> {
    let matches = state
        .get("service")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| {
            service.get("type").and_then(serde_json::Value::as_str)
                == Some("ArkretDeviceEnrollmentAuthority")
                && service
                    .get("serviceEndpoint")
                    .and_then(serde_json::Value::as_str)
                    == Some(authority_did.as_str())
        })
        .filter_map(|service| {
            service
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let [delegation] = matches.as_slice() else {
        anyhow::bail!("DID document does not contain one exact enrollment authority delegation");
    };
    if !delegation
        .strip_prefix(principal_id.as_str())
        .is_some_and(|fragment| fragment.starts_with('#') && fragment.len() > 1)
    {
        anyhow::bail!("enrollment authority delegation is not a local DID fragment");
    }
    Ok(delegation.clone())
}

async fn complete_identity_log(
    http: &arkret_sdk::http_client::Client,
    principal_id: &str,
) -> anyhow::Result<Vec<arkret_models_identity::DidKeyLogEntry>> {
    let mut events = Vec::new();
    let mut cursor = None;
    loop {
        let page = http
            .identity_log(principal_id, cursor.as_deref(), Some(100))
            .await?;
        events.extend(page.events);
        if !page.has_more {
            break;
        }
        let next = page
            .next_cursor
            .filter(|next| cursor.as_deref() != Some(next.as_str()))
            .ok_or_else(|| anyhow::anyhow!("DID history pagination did not advance"))?;
        cursor = Some(next);
    }
    events.sort_by_key(|event| event.seq);
    if events.first().is_none_or(|event| event.seq != 1)
        || events
            .windows(2)
            .any(|pair| pair[0].seq.checked_add(1) != Some(pair[1].seq))
    {
        anyhow::bail!("DID history is incomplete");
    }
    Ok(events)
}

fn recovery_backup_classes_unlocked(
    restore_payload: &serde_json::Value,
) -> anyhow::Result<Vec<arkret_models_crypto::RecoveryBackupClassUnlocked>> {
    let mut selected = restore_payload
        .get("backups")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|backup| {
            backup
                .get("ciphertext")
                .and_then(serde_json::Value::as_str)
                .is_some()
        })
        .filter(|backup| {
            let Some(backup_kind) = backup
                .get("backup_kind")
                .and_then(serde_json::Value::as_str)
            else {
                return false;
            };
            let Some(active_series) =
                super::selection::active_series_id_for_backup_class(restore_payload, backup_kind)
            else {
                return false;
            };
            backup.get("series_id").and_then(serde_json::Value::as_str) == Some(active_series)
        })
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left.get("backup_id")
            .and_then(serde_json::Value::as_str)
            .cmp(&right.get("backup_id").and_then(serde_json::Value::as_str))
    });
    selected
        .into_iter()
        .map(|backup| {
            Ok(arkret_models_crypto::RecoveryBackupClassUnlocked {
                backup_kind: arkret_models_crypto::BackupKind::try_from(
                    backup
                        .get("backup_kind")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("unlocked backup omitted backup_kind"))?,
                )
                .map_err(anyhow::Error::msg)?,
                backup_id: arkret_sdk::BackupId::new(
                    backup
                        .get("backup_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("unlocked backup omitted backup_id"))?,
                )?,
                series_id: arkret_sdk::BackupSeriesId::new(
                    backup
                        .get("series_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("unlocked backup omitted series_id"))?,
                )?,
                ciphertext_digest: Hash::new(
                    backup
                        .get("ciphertext_digest")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            anyhow::anyhow!("unlocked backup omitted ciphertext_digest")
                        })?,
                )?,
            })
        })
        .collect()
}

/// Exercise the product restore path for the joint recovery harness without
/// exposing the recovery-derived private key or plaintext account secret.
#[cfg(feature = "joint-test-api")]
#[doc(hidden)]
pub async fn unlock_joint_recovery_backups(
    principal_http: arkret_sdk::http_client::Client,
    session: &arkret_sdk::RecoverySessionState,
    recovery_words: &str,
) -> anyhow::Result<Vec<arkret_models_crypto::RecoveryBackupClassUnlocked>> {
    let api = crate::transport::TransportClient::from_http(
        principal_http,
        crate::transport::RequestContext::new(""),
    );
    let recovery_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        &api,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        session,
        &recovery_material,
    )
    .await?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let mut state_store = crate::state::LocalStateStore::default();
    let report = super::restore_mls_history_with_recovery_key_from_payload(
        &restore_payload,
        &mut state_store,
        secure_store.as_ref(),
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        &recovery_material.backup_hpke_serialized_private_key,
        (session.policy_id.as_str(), session.policy_version),
    )?;
    if !report.account_secret_imported || report.failed != 0 {
        anyhow::bail!(
            "joint recovery backup restore was incomplete: imported={}, failed={}",
            report.account_secret_imported,
            report.failed
        );
    }
    recovery_backup_classes_unlocked(&restore_payload)
}

fn apply_recovery_basis(event: &mut Event, basis: &LeaseBasisRef) {
    match basis {
        LeaseBasisRef::Seal(seal) => event.seal_ref = Some(seal.clone()),
        LeaseBasisRef::Joined(joined) => event.seal_basis = Some(joined.clone()),
        LeaseBasisRef::AnchorUnit(_) => {}
    }
}

fn authority_ticket_issue_request(
    transaction: &SecurityTransaction,
) -> anyhow::Result<RecoveryAuthorityTicketIssueRequest> {
    let authority_ticket_id = match &transaction.binding {
        SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)) => {
            binding.authority_ticket_id.clone()
        }
        _ => anyhow::bail!("authority ticket requires an enrollment-authority transaction"),
    };
    Ok(RecoveryAuthorityTicketIssueRequest {
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        authority_ticket_id,
        expected_next_step: IssueAuthorityTicketStep::IssueAuthorityTicket,
    })
}

pub(crate) fn authorize_recovery_device_request(
    transaction: &SecurityTransaction,
    ticket: RecoveryAuthorityTicket,
    account_authority_endpoint: &str,
    holder: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<arkret_wire::AuthorizeRecoveryDeviceRequest> {
    let authorization_preimage = match &transaction.prepared_plan {
        SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::EnrollmentAuthority(
            plan,
        )) => plan.authorization_preimage.clone(),
        _ => anyhow::bail!("device authorization requires an enrollment-authority plan"),
    };
    let mut request = arkret_wire::AuthorizeRecoveryDeviceRequest {
        ticket,
        authorization_preimage,
        canonical_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        holder_proof: RecoveryAuthorityHolderProof {
            dpop_jkt: holder.jkt().to_owned(),
            proof_jwt: String::new(),
        },
    };
    request.canonical_request_digest = request.expected_canonical_request_digest()?;
    request.holder_proof.proof_jwt = holder.mint_recovery_authority_proof(
        account_authority_endpoint,
        request.canonical_request_digest.as_str(),
        &format!("urn:uuid:{}", crate::operation::uuid_v7()),
    )?;
    request.validate_structural()?;
    Ok(request)
}

pub(crate) async fn execute_enrollment_authority_recovery(
    api: &crate::transport::TransportClient,
    principal_server_url: &str,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let (old_grant, holder) = {
        let mut store = state_store.write();
        let grant = store
            .session_grant()
            .ok_or_else(|| anyhow::anyhow!("recovery session grant is unavailable"))?;
        let holder =
            crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
                .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?;
        (grant, holder)
    };
    let prepared = prepare_enrollment_authority_recovery(
        api,
        principal_server_url,
        session,
        proof_outcome,
        recovery_words,
        holder.jkt(),
    )
    .await?;
    let verified_session = prepared.verified_session.clone();
    let session = &verified_session;
    // Unlock and durably import the backup snapshot while the transaction's
    // session-bound device generation is still the current trust generation.
    // Re-anchor deliberately advances that generation, so postponing restore
    // until afterward makes the accepted active-series signature look stale.
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let recovery_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        session,
        &recovery_material,
    )
    .await?;
    let restore_report = {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            prepared.recovery_private_key.as_slice(),
            (session.policy_id.as_str(), session.policy_version),
        )?
    };
    let restore_report_committed =
        restore_report.account_secret_imported && restore_report.failed == 0;
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    let transaction_id = prepared.create_request.transaction_id.clone();
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let staged_secret_ref = transaction_store
        .stage_secret(
            &transaction_id,
            Zeroizing::new(prepared.recovery_private_key.to_vec()),
        )
        .await
        .map_err(anyhow::Error::from)?;
    if let Err(error) = crate::security_transaction::store_pending_fresh_device_recovery(
        secure_store.as_ref(),
        &transaction_id,
    )
    .await
    {
        let _ = garth::SecurityTransactionStore::clear_staged_secret(
            &transaction_store,
            &staged_secret_ref,
        );
        return Err(error.into());
    }
    let principal_http = api.sdk_http_client()?;
    let engine = crate::security_transaction::security_transaction_engine(
        principal_http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let mut transaction = workflow
        .create_or_resume(prepared.create_request, Some(staged_secret_ref))
        .await
        .map_err(anyhow::Error::from)?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    while transaction.state != SecurityTransactionState::Completed
        && transaction.next_required_step != Some(SecurityTransactionStep::IssueTerminalReceipt)
    {
        let step = transaction.next_required_step.ok_or_else(|| {
            anyhow::anyhow!("recovery transaction omitted its next required step")
        })?;
        transaction = match step {
            SecurityTransactionStep::IssueAuthorityTicket => {
                principal_http
                    .issue_recovery_authority_ticket(&authority_ticket_issue_request(&transaction)?)
                    .await?;
                workflow
                    .refresh(&transaction_id)
                    .await
                    .map_err(anyhow::Error::from)?
            }
            SecurityTransactionStep::AuthorizeRecoveryDevice => {
                let ticket = principal_http
                    .issue_recovery_authority_ticket(&authority_ticket_issue_request(&transaction)?)
                    .await?;
                let participant_request = authorize_recovery_device_request(
                    &transaction,
                    ticket,
                    &prepared.account_authority_endpoint,
                    &holder,
                )?;
                workflow
                    .continue_with_signed_artifact(
                        &transaction_id,
                        &TypedSecurityTransactionContinueRequest {
                            request_digest: transaction.request_digest.clone(),
                            prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                            expected_next_step: step,
                            client_attestation: None,
                            participant_request: Some(participant_request),
                        },
                    )
                    .await
                    .map_err(anyhow::Error::from)?
            }
            SecurityTransactionStep::PublishDidEntry
            | SecurityTransactionStep::SubmitReanchorUnit => workflow
                .continue_with_signed_artifact(
                    &transaction_id,
                    &TypedSecurityTransactionContinueRequest {
                        request_digest: transaction.request_digest.clone(),
                        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                        expected_next_step: step,
                        client_attestation: None,
                        participant_request: None,
                    },
                )
                .await
                .map_err(anyhow::Error::from)?,
            _ => anyhow::bail!("enrollment-authority recovery reached unexpected step {step:?}"),
        };
    }

    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    if transaction.state != SecurityTransactionState::Completed
        && let Some(retried) = workflow
            .retry_byte_identical_pending(&transaction_id)
            .await
            .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    if transaction.state != SecurityTransactionState::Completed {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_terminal_receipt_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: prepared.proof_summary.kind,
                    proof_digest: prepared.proof_summary.proof_digest,
                    quorum_participant_count: None,
                    share_ids: None,
                },
                backup_classes_unlocked: recovery_backup_classes_unlocked(&restore_payload)?,
                welcome_count: 0,
                welcome_realm_summary: None,
                started_at: session.created_at,
                completed_at: crate::clock::now_utc(),
            },
            signer.as_ref(),
        )?;
        transaction = workflow
            .continue_with_signed_artifact(&transaction_id, &terminal)
            .await
            .map_err(anyhow::Error::from)?;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let transaction_completed_with_attestation = transaction.state
        == SecurityTransactionState::Completed
        && transaction
            .terminal_result
            .as_ref()
            .and_then(|result| result.completion_attestation.as_ref())
            .is_some();

    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(principal_server_url).await?;
    let account_sdk_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &authority.gate_account_base,
    )?;
    let account_http = arkret_sdk::http_client::ClientBuilder::new(account_sdk_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            holder.sdk_dpop_auth_for_access_token(old_grant.grant_jwt.clone()),
        ))
        .build()?;
    let account_engine =
        crate::security_transaction::security_transaction_engine(account_http, secure_store);
    let account_workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(account_engine);
    let promoted = match account_workflow
        .retry_byte_identical_promotion(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        Some(outcome) => outcome,
        None => {
            let endpoint = format!(
                "{}/recovery-session-grants/promote",
                authority.gate_account_base.trim_end_matches('/')
            );
            let request = account_workflow.build_holder_bound_promotion(
                &transaction_id,
                arkret_sdk::GrantId::new(old_grant.grant_id)?,
                &endpoint,
                &holder,
            )?;
            account_workflow
                .promote_holder_bound_grant(&transaction_id, &request)
                .await
                .map_err(anyhow::Error::from)?
        }
    };
    {
        let mut store = state_store.write();
        account_workflow.install_promoted_holder_bound_grant(
            &mut store,
            &promoted,
            principal_server_url,
            &holder,
        )?;
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    let refreshed_http =
        crate::identity::session_refresh::provide_authenticated_sdk_client(principal_server_url)
            .await?;
    let durable_device_authorized =
        crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
            &crate::transport::keys::query_keys(
                &refreshed_http,
                session.principal_id.as_str(),
                session.requesting_device_id.as_str(),
            )
            .await?,
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
        )?;
    let readiness = crate::fresh_device_recovery::RecoveryReadinessEvidence {
        transaction_completed_with_attestation,
        holder_bound_grant_refreshed: promoted.transaction_id == transaction_id,
        durable_device_authorized,
        durable_control_generation_matches: durable_device_authorized,
        restore_report_committed,
    };
    if readiness.is_ready() {
        crate::security_transaction::clear_pending_fresh_device_recovery(
            crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        )
        .map_err(anyhow::Error::from)?;
    }
    Ok(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness,
        restore_report,
    })
}

pub(crate) async fn resume_pending_fresh_device_recovery(
    api: &crate::transport::TransportClient,
    principal_server_url: &str,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    recovery_words: &str,
) -> anyhow::Result<Option<CompletedFreshDeviceRecovery>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let Some(transaction_id) =
        crate::security_transaction::pending_fresh_device_recovery(secure_store.as_ref())
            .map_err(anyhow::Error::from)?
    else {
        return Ok(None);
    };
    let principal_http = api.sdk_http_client()?;
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let local = garth::SecurityTransactionStore::load(&transaction_store, &transaction_id)
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| {
            anyhow::anyhow!("pending fresh-device recovery has no durable canonical create request")
        })?;
    let create: SecurityTransactionCreateRequest =
        serde_json::from_slice(&local.canonical_create_request)
            .map_err(|error| anyhow::anyhow!("decode pending recovery create request: {error}"))?;
    let SecurityTransactionCreateRequest::Recovery(create) = create else {
        anyhow::bail!("pending fresh-device recovery points to a non-recovery transaction");
    };
    let engine = crate::security_transaction::security_transaction_engine(
        principal_http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let mut transaction = workflow
        .create_or_resume(create, local.staged_secret_ref)
        .await
        .map_err(anyhow::Error::from)?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let recovery_session_id = match &transaction.binding {
        SecurityTransactionBinding::Recovery(binding) => binding.recovery_session_id().clone(),
        _ => anyhow::bail!("pending fresh-device recovery points to a non-recovery transaction"),
    };
    let session = api.recovery_session(recovery_session_id.as_str()).await?;
    session.validate()?;
    let proof_summary = session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    let holder = {
        let mut store = state_store.write();
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?
    };
    let account_authority_endpoint = if matches!(
        transaction.binding,
        SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(_))
    ) {
        let authority =
            crate::identity::account_auth::AuthorityResolver::discover(principal_server_url)
                .await?;
        Some(format!(
            "{}/recovery-device-authorizations",
            authority.gate_account_base.trim_end_matches('/')
        ))
    } else {
        None
    };
    while transaction.state != SecurityTransactionState::Completed
        && transaction.next_required_step != Some(SecurityTransactionStep::IssueTerminalReceipt)
    {
        let step = transaction.next_required_step.ok_or_else(|| {
            anyhow::anyhow!("recovery transaction omitted its next required step")
        })?;
        transaction = match step {
            SecurityTransactionStep::IssueAuthorityTicket => {
                principal_http
                    .issue_recovery_authority_ticket(&authority_ticket_issue_request(&transaction)?)
                    .await?;
                workflow
                    .refresh(&transaction_id)
                    .await
                    .map_err(anyhow::Error::from)?
            }
            SecurityTransactionStep::AuthorizeRecoveryDevice => {
                let ticket = principal_http
                    .issue_recovery_authority_ticket(&authority_ticket_issue_request(&transaction)?)
                    .await?;
                let participant_request = authorize_recovery_device_request(
                    &transaction,
                    ticket,
                    account_authority_endpoint.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("pending B-model recovery omitted Account Authority")
                    })?,
                    &holder,
                )?;
                workflow
                    .continue_with_signed_artifact(
                        &transaction_id,
                        &TypedSecurityTransactionContinueRequest {
                            request_digest: transaction.request_digest.clone(),
                            prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                            expected_next_step: step,
                            client_attestation: None,
                            participant_request: Some(participant_request),
                        },
                    )
                    .await
                    .map_err(anyhow::Error::from)?
            }
            SecurityTransactionStep::SubmitAuthorizeUnit
            | SecurityTransactionStep::PublishDidEntry
            | SecurityTransactionStep::SubmitReanchorUnit => workflow
                .continue_with_signed_artifact(
                    &transaction_id,
                    &TypedSecurityTransactionContinueRequest {
                        request_digest: transaction.request_digest.clone(),
                        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                        expected_next_step: step,
                        client_attestation: None,
                        participant_request: None,
                    },
                )
                .await
                .map_err(anyhow::Error::from)?,
            _ => anyhow::bail!("pending recovery reached unexpected step {step:?}"),
        };
    }

    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let recovery_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        &session,
        &recovery_material,
    )
    .await?;
    let restore_report = {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            &recovery_material.backup_hpke_serialized_private_key,
            (session.policy_id.as_str(), session.policy_version),
        )?
    };
    let restore_report_committed =
        restore_report.account_secret_imported && restore_report.failed == 0;
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }

    if transaction.state != SecurityTransactionState::Completed
        && let Some(retried) = workflow
            .retry_byte_identical_pending(&transaction_id)
            .await
            .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    if transaction.state != SecurityTransactionState::Completed {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_terminal_receipt_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: proof_summary.kind,
                    proof_digest: proof_summary.proof_digest,
                    quorum_participant_count: None,
                    share_ids: None,
                },
                backup_classes_unlocked: recovery_backup_classes_unlocked(&restore_payload)?,
                welcome_count: 0,
                welcome_realm_summary: None,
                started_at: session.created_at,
                completed_at: crate::clock::now_utc(),
            },
            signer.as_ref(),
        )?;
        transaction = workflow
            .continue_with_signed_artifact(&transaction_id, &terminal)
            .await
            .map_err(anyhow::Error::from)?;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let transaction_completed_with_attestation = transaction.state
        == SecurityTransactionState::Completed
        && transaction
            .terminal_result
            .as_ref()
            .and_then(|result| result.completion_attestation.as_ref())
            .is_some();

    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(principal_server_url).await?;
    let account_sdk_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &authority.gate_account_base,
    )?;
    let (old_grant, promotion_holder) = {
        let mut store = state_store.write();
        let grant = store
            .session_grant()
            .ok_or_else(|| anyhow::anyhow!("recovery session grant is unavailable"))?;
        let holder =
            crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
                .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?;
        (grant, holder)
    };
    let account_http = arkret_sdk::http_client::ClientBuilder::new(account_sdk_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            promotion_holder.sdk_dpop_auth_for_access_token(old_grant.grant_jwt.clone()),
        ))
        .build()?;
    let account_engine =
        crate::security_transaction::security_transaction_engine(account_http, secure_store);
    let account_workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(account_engine);
    let promoted = match account_workflow
        .retry_byte_identical_promotion(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        Some(outcome) => outcome,
        None => {
            let endpoint = format!(
                "{}/recovery-session-grants/promote",
                authority.gate_account_base.trim_end_matches('/')
            );
            let request = account_workflow.build_holder_bound_promotion(
                &transaction_id,
                arkret_sdk::GrantId::new(old_grant.grant_id)?,
                &endpoint,
                &promotion_holder,
            )?;
            account_workflow
                .promote_holder_bound_grant(&transaction_id, &request)
                .await
                .map_err(anyhow::Error::from)?
        }
    };
    {
        let mut store = state_store.write();
        account_workflow.install_promoted_holder_bound_grant(
            &mut store,
            &promoted,
            principal_server_url,
            &promotion_holder,
        )?;
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    let refreshed_http =
        crate::identity::session_refresh::provide_authenticated_sdk_client(principal_server_url)
            .await?;
    let durable_device_authorized =
        crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
            &crate::transport::keys::query_keys(
                &refreshed_http,
                session.principal_id.as_str(),
                session.requesting_device_id.as_str(),
            )
            .await?,
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
        )?;
    let readiness = crate::fresh_device_recovery::RecoveryReadinessEvidence {
        transaction_completed_with_attestation,
        holder_bound_grant_refreshed: promoted.transaction_id == transaction_id,
        durable_device_authorized,
        durable_control_generation_matches: durable_device_authorized,
        restore_report_committed,
    };
    if readiness.is_ready() {
        crate::security_transaction::clear_pending_fresh_device_recovery(
            crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        )
        .map_err(anyhow::Error::from)?;
    }
    Ok(Some(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness,
        restore_report,
    }))
}

pub(crate) async fn execute_cross_signing_recovery(
    api: &crate::transport::TransportClient,
    principal_server_url: &str,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let prepared =
        prepare_cross_signing_recovery(api, session, proof_outcome, recovery_words).await?;
    let verified_session = prepared.verified_session.clone();
    let session = &verified_session;
    let transaction_id = prepared.create_request.transaction_id.clone();
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let staged_secret_ref = transaction_store
        .stage_secret(
            &transaction_id,
            Zeroizing::new(prepared.recovery_private_key.to_vec()),
        )
        .await
        .map_err(anyhow::Error::from)?;
    if let Err(error) = crate::security_transaction::store_pending_fresh_device_recovery(
        secure_store.as_ref(),
        &transaction_id,
    )
    .await
    {
        let _ = garth::SecurityTransactionStore::clear_staged_secret(
            &transaction_store,
            &staged_secret_ref,
        );
        return Err(error.into());
    }
    let principal_http = api.sdk_http_client()?;
    let engine = crate::security_transaction::security_transaction_engine(
        principal_http.clone(),
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let mut transaction = workflow
        .create_or_resume(prepared.create_request, Some(staged_secret_ref))
        .await
        .map_err(anyhow::Error::from)?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    while transaction.state != SecurityTransactionState::Completed
        && transaction.next_required_step != Some(SecurityTransactionStep::IssueTerminalReceipt)
    {
        let step = transaction.next_required_step.ok_or_else(|| {
            anyhow::anyhow!("recovery transaction omitted its next required step")
        })?;
        if step != SecurityTransactionStep::SubmitAuthorizeUnit {
            anyhow::bail!("cross-signing recovery reached unexpected step {step:?}");
        }
        transaction = workflow
            .continue_with_signed_artifact(
                &transaction_id,
                &TypedSecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_next_step: step,
                    client_attestation: None,
                    participant_request: None,
                },
            )
            .await
            .map_err(anyhow::Error::from)?;
    }

    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let recovery_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        session,
        &recovery_material,
    )
    .await?;
    let restore_report = {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            prepared.recovery_private_key.as_slice(),
            (session.policy_id.as_str(), session.policy_version),
        )?
    };
    let restore_report_committed =
        restore_report.account_secret_imported && restore_report.failed == 0;
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }

    if transaction.state != SecurityTransactionState::Completed
        && let Some(retried) = workflow
            .retry_byte_identical_pending(&transaction_id)
            .await
            .map_err(anyhow::Error::from)?
    {
        transaction = retried;
    }
    if transaction.state != SecurityTransactionState::Completed {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_terminal_receipt_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: prepared.proof_summary.kind,
                    proof_digest: prepared.proof_summary.proof_digest,
                    quorum_participant_count: None,
                    share_ids: None,
                },
                backup_classes_unlocked: recovery_backup_classes_unlocked(&restore_payload)?,
                welcome_count: 0,
                welcome_realm_summary: None,
                started_at: session.created_at,
                completed_at: crate::clock::now_utc(),
            },
            signer.as_ref(),
        )?;
        transaction = workflow
            .continue_with_signed_artifact(&transaction_id, &terminal)
            .await
            .map_err(anyhow::Error::from)?;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let transaction_completed_with_attestation = transaction.state
        == SecurityTransactionState::Completed
        && transaction
            .terminal_result
            .as_ref()
            .and_then(|result| result.completion_attestation.as_ref())
            .is_some();

    let authority =
        crate::identity::account_auth::AuthorityResolver::discover(principal_server_url).await?;
    let account_sdk_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &authority.gate_account_base,
    )?;
    let (old_grant, holder) = {
        let mut store = state_store.write();
        let grant = store
            .session_grant()
            .ok_or_else(|| anyhow::anyhow!("recovery session grant is unavailable"))?;
        let holder =
            crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
                .ok_or_else(|| anyhow::anyhow!("recovery grant holder key is unavailable"))?;
        (grant, holder)
    };
    let account_http = arkret_sdk::http_client::ClientBuilder::new(account_sdk_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            holder.sdk_dpop_auth_for_access_token(old_grant.grant_jwt.clone()),
        ))
        .build()?;
    let account_engine =
        crate::security_transaction::security_transaction_engine(account_http, secure_store);
    let account_workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(account_engine);
    let promoted = match account_workflow
        .retry_byte_identical_promotion(&transaction_id)
        .await
        .map_err(anyhow::Error::from)?
    {
        Some(outcome) => outcome,
        None => {
            let endpoint = format!(
                "{}/recovery-session-grants/promote",
                authority.gate_account_base.trim_end_matches('/')
            );
            let request = account_workflow.build_holder_bound_promotion(
                &transaction_id,
                arkret_sdk::GrantId::new(old_grant.grant_id)?,
                &endpoint,
                &holder,
            )?;
            account_workflow
                .promote_holder_bound_grant(&transaction_id, &request)
                .await
                .map_err(anyhow::Error::from)?
        }
    };
    {
        let mut store = state_store.write();
        account_workflow.install_promoted_holder_bound_grant(
            &mut store,
            &promoted,
            principal_server_url,
            &holder,
        )?;
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }

    let refreshed_http =
        crate::identity::session_refresh::provide_authenticated_sdk_client(principal_server_url)
            .await?;
    let durable_device_authorized =
        crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
            &crate::transport::keys::query_keys(
                &refreshed_http,
                session.principal_id.as_str(),
                session.requesting_device_id.as_str(),
            )
            .await?,
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
        )?;
    let readiness = crate::fresh_device_recovery::RecoveryReadinessEvidence {
        transaction_completed_with_attestation,
        holder_bound_grant_refreshed: promoted.transaction_id == transaction_id,
        durable_device_authorized,
        durable_control_generation_matches: durable_device_authorized,
        restore_report_committed,
    };
    if readiness.is_ready() {
        crate::security_transaction::clear_pending_fresh_device_recovery(
            crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        )
        .map_err(anyhow::Error::from)?;
    }
    Ok(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness,
        restore_report,
    })
}
