use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::mls::persistence::MlsSnapshotEnvelope;
use crate::operation::trim_realm_id;
use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

pub(crate) struct RealmMlsAdmissionEvents {
    pub(crate) commit: arkret_sdk::Event,
    pub(crate) welcome: arkret_sdk::Event,
    pub(crate) snapshot: MlsSnapshotEnvelope,
}

pub(crate) struct RealmMlsBatchAdmissionEvents {
    pub(crate) commit: arkret_sdk::Event,
    pub(crate) welcomes: Vec<arkret_sdk::Event>,
    pub(crate) snapshot: MlsSnapshotEnvelope,
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

pub(crate) fn build_realm_mls_admission_events_from_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::MlsWelcomeClaimReceipt,
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
    actor_id: &str,
    device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::MlsWelcomeClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    let member_key_package = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))?;
    let (add, snapshot, previous_governance_binding) =
        crate::mls::runtime::build_add_member_commit_for_effective_scope(
            state_store,
            secure_store,
            realm_id,
            None,
            actor_id,
            device_id,
            &member_key_package,
        )
        .map_err(|err| err.user_message())?;
    let commit = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id,
        None,
        actor_id,
        &add.commit,
        &previous_governance_binding,
    )?;
    let governance_binding = commit
        .payload
        .get("governance_binding")
        .cloned()
        .ok_or_else(|| "MLS commit event missing governance_binding".to_owned())?;
    let governance_binding =
        serde_json::from_value::<arkret_sdk::MlsGovernanceBindingPayload>(governance_binding)
            .map_err(|err| format!("MLS commit governance_binding is invalid: {err}"))?;
    let welcome_payload = build_mls_welcome_payload(
        realm_id,
        actor_id,
        device_id,
        requester_device_authorize_event_id,
        claim,
        &member_key_package.keypackage_id,
        &add.welcome,
        &commit,
        governance_binding,
        claim_nonce,
        claim_receipt,
    )?;
    let welcome = crate::operation::ak_ops::mls_welcome_with_governance(
        realm_id,
        actor_id,
        &add.welcome.group_id,
        &welcome_payload,
    )
    .map_err(|err| format!("MLS Welcome typed payload conversion failed: {err}"))?
    .build_sdk_event("inkson")
    .map_err(|err| format!("MLS Welcome SDK Event conversion failed: {err}"))?;
    Ok(RealmMlsAdmissionEvents {
        commit,
        welcome,
        snapshot,
    })
}

pub(crate) fn build_realm_mls_admission_events_from_claims(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claims: &[(
        arkret_sdk::KeyPackageClaimRecord,
        String,
        arkret_sdk::MlsWelcomeClaimReceipt,
    )],
) -> Result<RealmMlsBatchAdmissionEvents, String> {
    build_mls_admission_events_from_claims_for_effective_scope(
        state_store,
        secure_store,
        realm_id,
        None,
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
    actor_id: &str,
    device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    claims: &[(
        arkret_sdk::KeyPackageClaimRecord,
        String,
        arkret_sdk::MlsWelcomeClaimReceipt,
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
            actor_id,
            device_id,
            &member_key_packages,
            sidecar_binding.clone(),
        )
        .map_err(|err| err.user_message())?;
    let commit = match sidecar_binding.as_ref() {
        Some(binding) => crate::mls::group_events::mls_commit_event_from_store_for_sidecar_scope(
            state_store,
            realm_id,
            actor_id,
            &add.commit,
            &previous_governance_binding,
            binding.clone(),
        )?,
        _ => crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
            state_store,
            realm_id,
            circle_id,
            actor_id,
            &add.commit,
            &previous_governance_binding,
        )?,
    };
    let governance_binding = commit
        .payload
        .get("governance_binding")
        .cloned()
        .ok_or_else(|| "MLS commit event missing governance_binding".to_owned())?;
    let governance_binding =
        serde_json::from_value::<arkret_sdk::MlsGovernanceBindingPayload>(governance_binding)
            .map_err(|err| format!("MLS commit governance_binding is invalid: {err}"))?;
    if add.welcomes.len() != claims.len() {
        return Err("MLS batch add returned a mismatched Welcome count".to_owned());
    }
    let mut welcomes = Vec::with_capacity(claims.len());
    for ((claim, claim_nonce, claim_receipt), (member_key_package, welcome_envelope)) in claims
        .iter()
        .zip(member_key_packages.iter().zip(add.welcomes.iter()))
    {
        let welcome_payload = build_mls_welcome_payload(
            realm_id,
            actor_id,
            device_id,
            requester_device_authorize_event_id,
            claim,
            &member_key_package.keypackage_id,
            welcome_envelope,
            &commit,
            governance_binding.clone(),
            claim_nonce,
            claim_receipt,
        )?;
        let welcome = crate::operation::ak_ops::mls_welcome_with_governance(
            realm_id,
            actor_id,
            &welcome_envelope.group_id,
            &welcome_payload,
        )
        .map_err(|err| format!("MLS Welcome typed payload conversion failed: {err}"))?
        .build_sdk_event("inkson")
        .map_err(|err| format!("MLS Welcome SDK Event conversion failed: {err}"))?;
        let mut welcome = welcome;
        if let Some(binding) = sidecar_binding.as_ref() {
            welcome.scope_ref = arkret_sdk::ScopeRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
                    .map_err(|error| format!("invalid Sidecar MLS Realm id: {error}"))?,
                sidecar_id: binding.sidecar_id.clone(),
            };
        } else if let Some(circle_id) = circle_id {
            welcome.scope_ref =
                crate::mls::group_events::circle_effective_scope(realm_id, circle_id)?;
        }
        welcomes.push(welcome);
    }
    Ok(RealmMlsBatchAdmissionEvents {
        commit,
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
    receipt: &arkret_sdk::MlsWelcomeClaimReceipt,
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

/// Build a `ak.realm_key.share` event carrying a HPKE-sealed bundle of
/// retained `history_secret`s so `recipient` can decrypt pre-join
/// `mls_exporter_aead_v1` content (`encryption-and-audit.md` history sharing).
///
/// `sealed_ciphertext` is the `base64url(eph_pub || ct)` blob produced by
/// [`crate::mls::secret_share::seal_history_secret_to_device_pubkey`] for the
/// recipient device's advertised HPKE public key. `from_epoch`/`to_epoch` bound
/// the shared range and are recorded in the `key_scope` so the receiver can
/// match the share to the epochs it is missing.
///
/// The provider MUST have built `sealed_ciphertext` against the recipient's
/// HPKE public key; this builder does not derive or validate that key.
///
/// `source_authorization_ref` is the durable policy/grant Control Move event
/// ref covering this delivery (encryption-and-audit.md §2.3.5(c)); the
/// registered payload schema requires it, so this fails closed on a
/// non-event-ref value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_realm_key_share_event(
    realm_id: &str,
    actor_id: &str,
    sender_device_id: &str,
    recipient_principal_id: &str,
    recipient_device_id: &str,
    from_epoch: u64,
    to_epoch: u64,
    policy_digest: String,
    sealed_ciphertext: String,
    source_authorization_ref: &str,
    authorization_grant_ref: &str,
) -> Result<arkret_sdk::Event, String> {
    let source_authorization_ref =
        arkret_sdk::EventId::new(source_authorization_ref.trim().to_owned())
            .map_err(|err| format!("invalid realm_key.share source_authorization_ref: {err:?}"))?;
    let recipient_did = crate::mls_api_helpers::principal_core_id(recipient_principal_id)
        .map_err(|err| format!("invalid realm_key.share recipient DID: {err:?}"))?;
    let policy_digest = arkret_sdk::Hash::new(policy_digest.trim().to_owned())
        .map_err(|err| format!("invalid realm_key.share policy_digest: {err:?}"))?;
    let digest_suite_name = policy_digest
        .as_str()
        .split_once(':')
        .map(|(suite, _)| suite)
        .ok_or_else(|| "realm_key.share policy_digest has no digest suite".to_owned())?;
    let digest_suite = arkret_sdk::canonical::digest_suite(digest_suite_name)
        .map_err(|err| format!("unsupported realm_key.share digest suite: {err}"))?;
    let authorization_grant_ref =
        arkret_sdk::GrantId::new(authorization_grant_ref.trim().to_owned())
            .map_err(|err| format!("invalid realm_key.share authorization grant ref: {err:?}"))?;
    let key_scope = arkret_sdk::RealmKeyScope {
        effective_scope: arkret_wire::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(trim_realm_id(realm_id))
                .map_err(|err| format!("invalid realm_key.share Realm id: {err:?}"))?,
        },
        policy_digest,
        membership_frontier_digest: None,
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
        history_visibility: None,
    };
    let mut payload = arkret_sdk::RealmKeySharePayload {
        share_kind: arkret_sdk::RealmKeyShareClass::MemberDevice,
        recipient_principal_id: recipient_did,
        target: arkret_sdk::RealmKeyShareTarget::MemberDevice {
            recipient_device_id: arkret_sdk::DeviceId::new(recipient_device_id.trim().to_owned())
                .map_err(|err| {
                format!("invalid realm_key.share recipient device id: {err:?}")
            })?,
        },
        sender_device_id: arkret_sdk::DeviceId::new(sender_device_id.trim().to_owned())
            .map_err(|err| format!("invalid realm_key.share sender device id: {err:?}"))?,
        source_authorization_ref,
        // Filled below with a real Ed25519 signature over
        // `RealmKeySharePayload::sender_signing_input()` (device-lifecycle.md
        // §13). Initialized empty only while constructing the signing input and
        // replaced before the Event is serialized. The per-secret HPKE seal
        // (AEAD tag) bound to the recipient device already covers confidentiality
        // + integrity of the shared keys; this detached signature additionally
        // authenticates the *sender device* to the receiver, independent of the
        // durable Event-envelope proof.
        sender_device_signature: arkret_sdk::SignatureMaterial::Variant1(BTreeMap::new()),
        key_scope,
        material: arkret_sdk::RealmKeyShareMaterial::Ciphertext {
            ciphertext: arkret_sdk::NonEmptyString::new(sealed_ciphertext)
                .map_err(|err| format!("invalid realm_key.share ciphertext: {err}"))?,
        },
        aad_digest: None,
        expires_at: None,
        created_at: crate::clock::now_utc_canonical(),
    };
    // Sign `sender_signing_input()` with this device's active Ed25519 event
    // signer and embed the detached signature. The registered payload schema
    // requires this signature, so a provider without an active signer must
    // fail closed and retry after device signing is ready.
    payload.sender_device_signature = sign_realm_key_share_sender_signature(&payload)
        .ok_or_else(|| "ak.realm_key.share requires an active sender device signer".to_owned())?;
    let event =
        crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmKeyShare>(
            realm_id, actor_id, payload,
        )
        .authorization_ref(authorization_grant_ref.as_str())
        .build_sdk_event("inkson")
        .map_err(|err| format!("ak.realm_key.share SDK Event conversion failed: {err}"))?;
    // The delivery-log append is derived from the registered contract, so the
    // producer no longer stamps it. `digest_suite` still has to be the one the
    // key scope's policy digest names, because the projection hashes the
    // delivery entry under it.
    arkret_sdk::schema::project_registered_cell_writes(&event, digest_suite)
        .map_err(|err| format!("ak.realm_key.share cell-write projection failed: {err}"))?;
    Ok(event)
}

/// Wrap an already-constructed [`arkret_sdk::RealmKeySharePayload`] (e.g. the
/// provider-initiated RRK seal produced by
/// `arkret_crypto::secret_share::seal_history_secret_to_device_pubkey`)
/// into a durable `ak.realm_key.share` Event, filling the
/// `sender_device_signature` with this device's active Ed25519 signer. The
/// registered payload schema requires this signature, so this fails closed when
/// no active signer is installed.
///
/// Unlike [`build_realm_key_share_event`], the seal + payload are already done by
/// the SDK authority; this only authenticates the sender device and converts to
/// a wire Event.
pub(crate) fn wrap_realm_key_share_payload_event(
    realm_id: &str,
    actor_id: &str,
    mut payload: arkret_sdk::RealmKeySharePayload,
    authorization_grant_ref: &str,
) -> Result<arkret_sdk::Event, String> {
    let digest_suite_name = payload
        .key_scope
        .policy_digest
        .as_str()
        .split_once(':')
        .map(|(suite, _)| suite)
        .ok_or_else(|| "realm_key.share policy_digest has no digest suite".to_owned())?;
    let digest_suite = arkret_sdk::canonical::digest_suite(digest_suite_name)
        .map_err(|err| format!("unsupported realm_key.share digest suite: {err}"))?;
    let authorization_grant_ref =
        arkret_sdk::GrantId::new(authorization_grant_ref.trim().to_owned())
            .map_err(|err| format!("invalid realm_key.share authorization grant ref: {err:?}"))?;
    payload.sender_device_signature = sign_realm_key_share_sender_signature(&payload)
        .ok_or_else(|| "ak.realm_key.share requires an active sender device signer".to_owned())?;
    let event =
        crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmKeyShare>(
            realm_id, actor_id, payload,
        )
        .authorization_ref(authorization_grant_ref.as_str())
        .build_sdk_event("inkson")
        .map_err(|err| format!("ak.realm_key.share SDK Event conversion failed: {err}"))?;
    // The delivery-log append is derived from the registered contract, so the
    // producer no longer stamps it. `digest_suite` still has to be the one the
    // key scope's policy digest names, because the projection hashes the
    // delivery entry under it.
    arkret_sdk::schema::project_registered_cell_writes(&event, digest_suite)
        .map_err(|err| format!("ak.realm_key.share cell-write projection failed: {err}"))?;
    Ok(event)
}

/// Sign the canonical `RealmKeySharePayload::sender_signing_input()` with this
/// device's active Ed25519 event signer (raw signature over canonical JSON,
/// not a detached JWS — the receiver verifies the raw signature in
/// [`crate::mls::runtime::verify_realm_key_share_sender_signature`]).
///
/// Returns a typed `sender_device_signature` object:
/// ```json
/// { "signature_algorithm": "Ed25519", "signature": "<b64url>", "signer_public_key_multibase": "z.." }
/// ```
/// or `None` when no raw-capable signer is installed.
pub(crate) fn sign_realm_key_share_sender_signature(
    payload: &arkret_sdk::RealmKeySharePayload,
) -> Option<arkret_sdk::SignatureMaterial> {
    let signer = crate::event_signer::active_signer()?;
    let pubkey_multibase = signer.public_key_multibase()?;
    // Canonicalization failure must not degrade into signing empty bytes.
    let signing_input = payload.sender_signing_input().ok()?;
    let signature = signer.sign_raw(&signing_input).ok()?;
    let mut fields = BTreeMap::new();
    fields.insert(
        "signature_algorithm".to_owned(),
        Value::String("Ed25519".to_owned()),
    );
    fields.insert(
        "signature".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(signature)),
    );
    fields.insert(
        "signer_public_key_multibase".to_owned(),
        Value::String(pubkey_multibase),
    );
    Some(arkret_sdk::SignatureMaterial::Variant1(fields))
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
    commit_event: &arkret_sdk::Event,
    governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
    claim_nonce: &str,
    claim_receipt: &arkret_sdk::MlsWelcomeClaimReceipt,
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
        commit_ref: Some(commit_event.event_id.clone()),
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
    use serde_json::json;

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;
    use crate::state::isolated_store_for_tests;

    struct ActiveSignerGuard {
        _guard: crate::event_signer::ActiveSignerTestGuard,
    }

    impl ActiveSignerGuard {
        fn install(seed: [u8; 32], signer_did: &str) -> Self {
            let signer =
                std::sync::Arc::new(crate::event_signer::build_ed25519_signer(seed, signer_did));
            Self {
                _guard: crate::event_signer::ActiveSignerTestGuard::replace(Some(signer)),
            }
        }
    }

    fn claim_from_key_package(
        record: &arkret_sdk::MlsKeyPackageRecord,
        device_authorize_event_id: &str,
    ) -> arkret_sdk::KeyPackageClaimRecord {
        let (principal_id, device_id) = match &record.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime { .. } => {
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
    ) -> arkret_sdk::MlsWelcomeClaimReceipt {
        let request = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: arkret_sdk::Base64UrlString::new(claim_nonce.to_owned()).unwrap(),
            target_principal_id: claim.principal_id.clone(),
            intended_realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            requester: crate::mls_api_helpers::principal_core_id(requester).unwrap(),
            mls_group_id: arkret_sdk::NonEmptyString::new(
                crate::mls::runtime::mls_group_id_for_realm(realm_id),
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
    fn realm_key_share_event_matches_registered_payload_schema() {
        let _signer_guard =
            ActiveSignerGuard::install([9u8; 32], "did:key:zRealmKeyShareSchemaTest");
        let realm = "ak:realm:AYLi9-CkMrvB65FQ_HLu_5w83MhPZH0RYn8AEhK7ADLy";
        let policy_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let event = build_realm_key_share_event(
            realm,
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
            "did:web:bob.example",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
            0,
            2,
            policy_digest.clone(),
            "c2VhbGVk".to_owned(),
            "ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc",
            "ak:grant:AYhEOew9OY47Elo3DUdM-vG441-UQbeQzZosnACQC6QU",
        )
        .unwrap();

        let catalog = arkret_sdk::schema::event_payload_validator_catalog().unwrap();
        catalog
            .validate_payload(
                event.kind.as_str(),
                &serde_json::to_value(&event.payload).unwrap(),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "ak.realm_key.share payload violates registered schema: {err}\npayload: {}",
                    serde_json::to_string_pretty(&event.payload).unwrap()
                )
            });
        assert_eq!(
            event.payload["key_scope"]["effective_scope"],
            json!({ "kind": "realm", "realm_id": realm })
        );
        assert_eq!(event.payload["key_scope"]["policy_digest"], policy_digest);
        assert!(
            !event
                .payload
                .contains_key("requester_device_authorize_event_id")
        );
        assert_eq!(
            event.authorization_ref.as_deref(),
            Some("ak:grant:AYhEOew9OY47Elo3DUdM-vG441-UQbeQzZosnACQC6QU")
        );
        // v1 derives the delivery-log write from the registry instead of
        // shipping it: assert the projection, which is what the receiver runs.
        let writes = crate::operation::direct_registered_cell_writes(&event).unwrap();
        assert_eq!(writes.len(), 1);
        let cell = arkret_sdk::CellId::from_ref(&writes[0].cell).unwrap();
        assert_eq!(
            cell.component(),
            arkret_wire::CellFamilyId::REALM_KEY_DELIVERY_V1
        );
        assert_eq!(
            arkret_sdk::events::cba_cell_family_plane(cell.component()),
            Some(arkret_sdk::events::CbaEffectPlane::Data)
        );
        let created_at = event.payload["created_at"]
            .as_str()
            .expect("realm_key.share created_at is a string");
        arkret_sdk::canonical::validate_timestamp_canonical(created_at)
            .expect("realm_key.share created_at is canonical RFC3339 UTC");
    }

    #[cfg(not(target_arch = "wasm32"))]
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
        let error = build_realm_mls_admission_events_from_claim(
            &alice_state,
            &secure,
            realm,
            alice,
            alice_device,
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
