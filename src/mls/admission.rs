//! Admitting a claimed endpoint into a scope's MLS group.
//!
//! One admission produces exactly one shared Event — the `ak.mls.commit` that
//! carries the Add inline — plus one producer-signed `MlsWelcomeDelivery` per
//! added endpoint. The Station commits the Event into the scope's own stream
//! and queues the deliveries in the same atomic submission, so a recipient can
//! never be handed a Welcome for a Commit that was not accepted, and the
//! inviter installs its staged group state as soon as the submission is
//! accepted rather than waiting for any recipient acknowledgement.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::mls::persistence::MlsLocalCheckpointEnvelope;
use crate::operation::trim_realm_id;
use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

/// Serialize admission and coverage authoring against the same Realm's
/// installed private state. Durable outbound ownership is checked under this
/// lock so a restart cannot mint over a queued transition.
pub(crate) fn mls_admission_authoring_lock(realm_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(realm_id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(realm_id.to_owned(), Arc::downgrade(&lock));
    lock
}

/// Build the Welcome deliveries once the Commit they bind has been authored.
///
/// A delivery names `commit_event_ref`, which only exists after the Commit
/// Event is authored and signed, so the deliveries cannot be produced any
/// earlier without binding an id that is still moving.
pub(crate) type WelcomeDeliveryStep = Box<
    dyn FnOnce(&arkret_sdk::Event) -> Result<Vec<arkret_wire::MlsWelcomeDelivery>, String> + Send,
>;

/// The complete atomic MLS admission unit.
pub(crate) struct RealmMlsAdmissionEvents {
    /// The `ak.mls.commit` write to author and submit.
    pub(crate) commit: crate::operation::LocalOperation,
    /// Produces the Welcome deliveries for the authored Commit.
    pub(crate) welcomes: WelcomeDeliveryStep,
    /// The verified claim evidence the post-transition attribution needs.
    pub(crate) authority_hints: Vec<crate::mls::governance_proof::MlsLeafAuthorityHint>,
    /// The staged group state installed once the submission is accepted.
    pub(crate) staged_checkpoint: MlsLocalCheckpointEnvelope,
}

/// How the inviting client proves it authored a Welcome delivery.
#[derive(Clone)]
pub(crate) enum WelcomeRequester {
    /// An ordinary account device signing with its own device method.
    Device {
        sender_device_id: arkret_sdk::DeviceId,
    },
}

fn admission_actor_and_requester(
    state_store: &LocalStateStore,
    realm_id: &str,
    ordinary_actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
) -> Result<(String, WelcomeRequester), String> {
    if state_store.realm_projection_has_retired_minimal_metadata_marker(realm_id) {
        return Err("retired minimal-metadata Realm marker blocks MLS admission".to_owned());
    }
    Ok((
        ordinary_actor_id.to_owned(),
        WelcomeRequester::Device {
            sender_device_id: device_id.clone(),
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
    requester_device_authorize_event_id(&account.devices, &device_id).ok_or_else(|| {
            "current requester device has no accepted device.authorize Event; Welcome authoring is fail-closed"
                .to_owned()
        })
}

fn requester_device_authorize_event_id(
    devices: &[arkret_sdk::AccountDeviceSummary],
    device_id: &arkret_sdk::DeviceId,
) -> Option<arkret_sdk::EventId> {
    devices
        .iter()
        .find(|device| {
            &device.device_id == device_id
                && device.status == arkret_sdk::DeviceSummaryStatus::Active
                && device.verification_state == arkret_sdk::DeviceSummaryVerificationState::Verified
                && device.validate().is_ok()
        })
        .and_then(|device| device.authorized_event_ref.clone())
}

/// Build the complete admission unit for one claimed KeyPackage.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_realm_mls_admission_events_from_claim(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    realm_id: &str,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    build_admission_events_for_scope(
        state_store,
        secure_store,
        &realm_effective_scope(realm_id)?,
        authority,
        actor_id,
        device_id,
        claim,
        claim_request_id,
        claim_receipt,
    )
}

fn realm_effective_scope(realm_id: &str) -> Result<arkret_sdk::ScopeRef, String> {
    Ok(arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(trim_realm_id(realm_id))
            .map_err(|error| format!("invalid admission Realm id: {error}"))?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_admission_events_for_scope(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    claim_receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<RealmMlsAdmissionEvents, String> {
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS admission scope has no Realm".to_owned())?
        .clone();
    let (actor_id, requester) =
        admission_actor_and_requester(state_store, realm_id.as_str(), actor_id, device_id)?;
    validate_claim_receipt_for_admission(
        state_store,
        effective_scope,
        authority,
        claim,
        claim_request_id,
        claim_receipt,
    )?;
    let target_actor = crate::mls::governance_proof::claimed_actor_id(claim, claim_receipt)?;
    let member_key_package = crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
        .map_err(|err| format!("MLS KeyPackage claim decode failed: {err}"))?;
    let member_authority_hint =
        crate::mls::governance_proof::leaf_authority_hint_from_claim(claim)?;
    let (add, staged) = crate::mls::runtime::build_add_member_commit_for_scope(
        state_store,
        secure_store,
        effective_scope,
        authority,
        device_id,
        &member_key_package,
        std::slice::from_ref(&member_authority_hint),
        Some(&target_actor),
    )
    .map_err(|err| err.user_message())?;

    let circle_id = match effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str().to_owned()),
        _ => None,
    };
    let commit = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
        state_store,
        realm_id.as_str(),
        circle_id.as_deref(),
        &actor_id,
        &staged.envelope,
    )?;
    let welcome_scope = effective_scope.clone();
    let welcome_draft = add.welcome.clone();
    let welcomes: WelcomeDeliveryStep = Box::new(move |commit_event| {
        if commit_event.kind != arkret_sdk::EventKind::MlsCommit
            || commit_event.scope_ref != welcome_scope
        {
            return Err(
                "MLS Welcome deliveries must bind the exact authored Commit and scope".to_owned(),
            );
        }
        Ok(vec![build_welcome_delivery(
            &realm_id,
            &welcome_scope,
            &commit_event.event_id,
            &target_actor,
            &welcome_draft,
            &requester,
            &actor_id,
        )?])
    });
    Ok(RealmMlsAdmissionEvents {
        commit,
        welcomes,
        authority_hints: vec![member_authority_hint],
        staged_checkpoint: staged.staged_checkpoint,
    })
}

fn validate_claim_receipt_for_admission(
    state_store: &LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    authority: &arkret_sdk::AccountId,
    claim: &arkret_sdk::KeyPackageClaimRecord,
    claim_request_id: &str,
    receipt: &arkret_sdk::PeerKeyPackageClaimReceipt,
) -> Result<(), String> {
    let expected_realm = effective_scope
        .realm_id_opt()
        .ok_or_else(|| "MLS admission scope has no Realm".to_owned())?;
    // The receipt names the requester as a complete account; it is compared as
    // one value, never by principal alone.
    if receipt.request.requester_account_id.as_ref() != Some(authority)
        || receipt.request.target_principal_id().as_ref() != Some(&claim.principal_id)
        || &receipt.request.intended_realm_id != expected_realm
        || receipt.request.claim_request_id.as_str() != claim_request_id
    {
        return Err(
            "KeyPackage claim receipt does not match the exact requester, target, Realm, MLS group, and claim request id"
                .to_owned(),
        );
    }
    let expected_group = state_store
        .mls_checkpoint_for_scope(effective_scope)
        .map(|snapshot| snapshot.group_id)
        .ok_or_else(|| "MLS admission requires a current local group checkpoint".to_owned())?;
    if receipt.request.mls_group_id.as_str() != expected_group {
        return Err("KeyPackage claim receipt MLS group does not match local state".to_owned());
    }
    arkret_sdk::validate_target_claim_evidence(claim, receipt).map_err(|error| {
        format!("KeyPackage claim did not satisfy its exact target selector: {error}")
    })?;
    Ok(())
}

/// The wire recipient endpoint one Welcome draft is addressed to.
fn welcome_recipient_endpoint(
    recipient: &arkret_sdk::MlsEndpointIdentity,
) -> Result<arkret_wire::MlsWelcomeRecipientEndpoint, String> {
    match recipient {
        arkret_sdk::MlsEndpointIdentity::HumanDevice { device_id, .. } => {
            Ok(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id.clone(),
            })
        }
        arkret_sdk::MlsEndpointIdentity::AgentRuntime {
            verification_method,
            ..
        } => Ok(arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: verification_method.clone(),
        }),
        // `MlsWelcomeRecipientEndpoint` has no minimal-metadata pairwise
        // variant, so a delivery cannot be addressed to a pairwise endpoint.
        // Fail closed rather than mislabel the recipient as a device.
        arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
            Err("a Welcome delivery cannot address a minimal-metadata pairwise endpoint".to_owned())
        }
    }
}

/// Build and sign one `MlsWelcomeDelivery` for an accepted-to-be Commit.
///
/// The delivery binds the exact Commit Event it travels with, so the Station's
/// atomic submission is what makes it deliverable; a delivery whose Commit is
/// rejected is never queued.
fn build_welcome_delivery(
    realm_id: &arkret_sdk::RealmId,
    effective_scope: &arkret_sdk::ScopeRef,
    commit_event_ref: &arkret_sdk::EventId,
    recipient_actor_id: &arkret_sdk::ActorId,
    draft: &arkret_sdk::mls::MlsWelcomeDraft,
    requester: &WelcomeRequester,
    requester_actor_id: &str,
) -> Result<arkret_wire::MlsWelcomeDelivery, String> {
    let recipient_endpoint = welcome_recipient_endpoint(&draft.recipient)?;
    let welcome_id = arkret_wire::MlsWelcomeDeliveryId::new(
        arkret_sdk::identifiers::new_prefixed_uuid7("ak:mls_welcome_delivery:"),
    )
    .map_err(|error| format!("invalid Welcome delivery id: {error}"))?;
    let unsigned = UnsignedWelcomeDelivery {
        welcome_id,
        realm_id: realm_id.clone(),
        effective_scope: effective_scope.clone(),
        commit_event_ref: commit_event_ref.clone(),
        recipient_actor_id: recipient_actor_id.clone(),
        recipient_endpoint,
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_b64: draft.ciphertext_b64.clone(),
    };
    let WelcomeRequester::Device { sender_device_id } = requester;
    let body = unsigned.unsigned_body();
    let signed_digest = arkret_signatures::detached_object::detached_object_signed_digest(&body)
        .map_err(|error| format!("Welcome delivery signed digest: {error}"))?;
    let created_at = arkret_sdk::canonical::normalize_timestamp_canonical(crate::clock::now_utc());
    let (verification_method, signature) =
        sign_with_active_device_signer(requester_actor_id, sender_device_id, |method| {
            arkret_signatures::detached_object::detached_object_signing_bytes(
                arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                method,
                &signed_digest,
                created_at,
            )
            .map_err(|error| format!("Welcome delivery signing transcript: {error}"))
        })?;
    let producer_proof = arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method,
        signed_digest,
        created_at,
        sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
            .map_err(|error| format!("Welcome delivery signature encoding: {error}"))?,
    };
    let delivery = unsigned.into_delivery(producer_proof);
    delivery
        .validate_shape()
        .map_err(|error| format!("invalid Welcome delivery: {error}"))?;
    Ok(delivery)
}

/// The Welcome delivery body before its producer proof is attached.
struct UnsignedWelcomeDelivery {
    welcome_id: arkret_wire::MlsWelcomeDeliveryId,
    realm_id: arkret_sdk::RealmId,
    effective_scope: arkret_sdk::ScopeRef,
    commit_event_ref: arkret_sdk::EventId,
    recipient_actor_id: arkret_sdk::ActorId,
    recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint,
    keypackage_claim_ref: arkret_wire::KeypackageClaimId,
    ciphertext_b64: arkret_sdk::Base64UrlString,
}

impl UnsignedWelcomeDelivery {
    /// The closed delivery minus `producer_proof`: the body
    /// `ak.mls_welcome_delivery_signature.v1` seals (encryption-and-audit.md
    /// §2.6.1).
    fn unsigned_body(&self) -> serde_json::Value {
        serde_json::json!({
            "welcome_id": self.welcome_id,
            "realm_id": self.realm_id,
            "effective_scope": self.effective_scope,
            "commit_event_ref": self.commit_event_ref,
            "recipient_actor_id": self.recipient_actor_id,
            "recipient_endpoint": self.recipient_endpoint,
            "keypackage_claim_ref": self.keypackage_claim_ref,
            "ciphertext_b64": self.ciphertext_b64,
        })
    }

    fn into_delivery(
        self,
        producer_proof: arkret_wire::DetachedObjectSignature,
    ) -> arkret_wire::MlsWelcomeDelivery {
        arkret_wire::MlsWelcomeDelivery {
            welcome_id: self.welcome_id,
            realm_id: self.realm_id,
            effective_scope: self.effective_scope,
            commit_event_ref: self.commit_event_ref,
            recipient_actor_id: self.recipient_actor_id,
            recipient_endpoint: self.recipient_endpoint,
            keypackage_claim_ref: self.keypackage_claim_ref,
            ciphertext_b64: self.ciphertext_b64,
            producer_proof,
        }
    }
}

/// Sign with the exact active device method, refusing any other signer. The
/// signed bytes are built from that method, which the transcript covers.
fn sign_with_active_device_signer(
    actor_id: &str,
    sender_device_id: &arkret_sdk::DeviceId,
    signing_bytes: impl FnOnce(&arkret_sdk::DidUrl) -> Result<Vec<u8>, String>,
) -> Result<(arkret_sdk::DidUrl, Vec<u8>), String> {
    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("inkson")
            .map_err(|err| format!("Welcome delivery device signer bootstrap: {err}"))?,
    };
    let signer_did = arkret_sdk::Did::new(signer.signer_did().to_owned())
        .map_err(|err| format!("Welcome delivery signer DID: {err}"))?;
    let signer_actor_id = arkret_sdk::project_did_to_core_id(&signer_did)
        .map_err(|err| format!("Welcome delivery signer actor projection: {err}"))?;
    if signer_actor_id.as_str() != actor_id {
        return Err(
            "Welcome delivery active signer DID does not project to the requester actor".to_owned(),
        );
    }
    let expected_kid = format!("{signer_did}#{}", sender_device_id.as_str());
    if signer.verification_method() != expected_kid {
        return Err(
            "Welcome delivery active signer is not the exact requester device method".to_owned(),
        );
    }
    let verification_method = arkret_sdk::DidUrl::new(expected_kid)
        .map_err(|err| format!("Welcome delivery signing method: {err}"))?;
    let bytes = signing_bytes(&verification_method)?;
    let signature = signer
        .sign_raw(&bytes)
        .map_err(|err| format!("Welcome delivery device signature: {err}"))?;
    Ok((verification_method, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::isolated_store_for_tests;

    const REALM: &str = "ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx";

    #[test]
    fn retired_minimal_metadata_marker_rejects_admission_before_signing() {
        let mut state = isolated_store_for_tests("retired-minimal-admission");
        state.save_realm_tree_projection(
            REALM,
            serde_json::json!({"schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"]}),
        );
        let device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1".to_owned())
                .unwrap();
        assert!(
            admission_actor_and_requester(&state, REALM, "did:web:alice.example", &device)
                .err()
                .unwrap()
                .contains("retired minimal-metadata")
        );
    }

    fn requester_device_summary(
        device_id: &arkret_sdk::DeviceId,
        status: &str,
        authorized_event_ref: Option<serde_json::Value>,
    ) -> arkret_sdk::AccountDeviceSummary {
        let mut value = serde_json::json!({
            "device_id": device_id,
            "status": status,
            "verification_state": if authorized_event_ref.is_some() { "verified" } else { "unresolved" },
            "verification_source": if authorized_event_ref.is_some() {
                serde_json::Value::String("pairing_code".to_owned())
            } else {
                serde_json::Value::Null
            }
        });
        if let Some(authorized_event_ref) = authorized_event_ref {
            value["authorized_event_ref"] = authorized_event_ref;
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn welcome_requester_uses_active_device_committed_authorization_event() {
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let event_id =
            arkret_sdk::EventId::new("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
                .unwrap();
        let active =
            requester_device_summary(&device_id, "active", Some(serde_json::json!(event_id)));
        let expected = active.authorized_event_ref.clone().unwrap();

        assert_eq!(
            requester_device_authorize_event_id(&[active], &device_id),
            Some(expected)
        );
    }

    #[test]
    fn welcome_requester_rejects_revoked_or_uncommitted_device() {
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let authorized_event_ref =
            serde_json::json!("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e");
        let revoked = requester_device_summary(&device_id, "revoked", Some(authorized_event_ref));
        let active_without_commit = requester_device_summary(&device_id, "active", None);

        assert!(requester_device_authorize_event_id(&[revoked], &device_id).is_none());
        assert!(
            requester_device_authorize_event_id(&[active_without_commit], &device_id).is_none()
        );
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
            _ => panic!("test fixture requires a human-device record"),
        };
        arkret_sdk::KeyPackageClaimRecord {
            claim_id: "ak:keypackage_claim:01904100-0000-7000-8000-00000000000a".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            actor_id: record.actor_id.clone(),
            principal_id,
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
        let intended_realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap();
        let mls_group_id = garth::mls::mls_group_id_for_realm(&intended_realm_id)
            .expect("test Realm scope must derive a canonical MLS group id");
        let request = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: arkret_sdk::Base64UrlString::new(claim_request_id.to_owned())
                .unwrap(),
            target_account_id: Some(claim.actor_id.as_account_id().unwrap().clone()),
            intended_realm_id,
            requester_account_id: Some(arkret_sdk::AccountId::new(
                crate::mls_api_helpers::principal_core_id(requester).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            )),
            mls_group_id,
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
            destination_id: claim.actor_id.as_account_id().unwrap().station_id.clone(),
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
    fn claimed_actor_must_match_receipt_destination_station() {
        let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::test_support::account_actor("did:web:bob.example"),
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1").unwrap(),
        )
        .unwrap();
        let claim = claim_from_key_package(
            &bob.key_package_record().unwrap(),
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        );
        let mut receipt = self_claim_receipt(&claim, REALM, "did:web:alice.example", "Y2xhaW0");
        let alpha = crate::mls::governance_proof::claimed_actor_id(&claim, &receipt).unwrap();
        assert_eq!(alpha, claim.actor_id);
        receipt.destination_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:beta.example").unwrap();
        assert_eq!(
            crate::mls::governance_proof::claimed_actor_id(&claim, &receipt).unwrap_err(),
            "claimed KeyPackage actor_id differs from receipt destination"
        );
    }

    #[test]
    fn a_welcome_delivery_addresses_the_claimed_endpoint_or_fails_closed() {
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000b1".to_owned())
                .unwrap();
        let principal = crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap();
        assert_eq!(
            welcome_recipient_endpoint(&arkret_sdk::MlsEndpointIdentity::human_device(
                principal.clone(),
                device_id.clone()
            ))
            .unwrap(),
            arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id }
        );
        let method = arkret_sdk::DidUrl::new("did:web:agent.example#runtime-1").unwrap();
        let agent = arkret_sdk::MlsEndpointIdentity::agent_runtime(
            crate::mls_api_helpers::principal_core_id("did:web:agent.example").unwrap(),
            method.clone(),
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            welcome_recipient_endpoint(&agent).unwrap(),
            arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: method
            }
        );
        let pairwise = arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
            arkret_sdk::DidCoreId::new(
                "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x".to_owned(),
            )
            .unwrap(),
            arkret_sdk::DidUrl::new(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x".to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(welcome_recipient_endpoint(&pairwise).is_err());
    }

    #[test]
    fn the_signing_body_excludes_the_producer_proof_and_binds_every_other_field() {
        let unsigned = UnsignedWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000009".to_owned(),
            )
            .unwrap(),
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
            effective_scope: arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
            },
            commit_event_ref: arkret_sdk::EventId::new(
                "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
            )
            .unwrap(),
            recipient_actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            )),
            recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: arkret_sdk::DeviceId::new(
                    "ak:device:01904100-0000-7000-8000-0000000000b1".to_owned(),
                )
                .unwrap(),
            },
            keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(
                "ak:keypackage_claim:01904100-0000-7000-8000-00000000000a".to_owned(),
            )
            .unwrap(),
            ciphertext_b64: arkret_sdk::Base64UrlString::new("AQID").unwrap(),
        };
        let body = unsigned.unsigned_body();
        let object = body.as_object().unwrap();
        assert!(!object.contains_key("producer_proof"));
        let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "ciphertext_b64",
                "commit_event_ref",
                "effective_scope",
                "keypackage_claim_ref",
                "realm_id",
                "recipient_actor_id",
                "recipient_endpoint",
                "welcome_id",
            ]
        );
        let delivery = unsigned.into_delivery(arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
            signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: "2026-09-16T00:00:00.000Z".parse().unwrap(),
            sig: arkret_sdk::Base64UrlString::new("AA").unwrap(),
        });
        let mut expected = serde_json::to_value(&delivery).unwrap();
        expected.as_object_mut().unwrap().remove("producer_proof");
        assert_eq!(
            body, expected,
            "the sealed body is the delivery minus its proof"
        );
    }

    #[test]
    fn a_mismatched_claim_target_cannot_authorize_an_admission() {
        let alice_state = isolated_store_for_tests("peer-self-claim-fail-closed");
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let alice = "did:web:alice.example";
        let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b1";
        let bob_identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            crate::test_support::account_actor("did:web:bob.example"),
            arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
        )
        .unwrap();
        let claim = claim_from_key_package(
            &bob_identity.key_package_record().unwrap(),
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        );
        let claim_request_id = "Y2xhaW0tcmVxdWVzdC0wMTIzNDU2Nzg5";
        let mut claim_receipt = self_claim_receipt(&claim, REALM, alice, claim_request_id);
        claim_receipt.request.target_account_id = Some(arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(alice).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        ));
        let authority = arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(alice).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        let alice_device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
                .unwrap();
        let error = build_realm_mls_admission_events_from_claim(
            &alice_state,
            &secure,
            REALM,
            &authority,
            alice,
            &alice_device,
            &claim,
            claim_request_id,
            &claim_receipt,
        )
        .err()
        .expect("a remote claim must fail before any MLS state mutation");
        assert!(
            error.contains("does not match the exact requester"),
            "{error}"
        );
        assert!(alice_state.mls_checkpoint_for(REALM).is_none());
    }
}
