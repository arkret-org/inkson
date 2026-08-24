use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

const HISTORY_REQUEST_HPKE_PRIVATE_KEY_PREFIX: &str =
    "inkson.history_request_hpke_x25519.private.v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryResponsePageInstallOutcome {
    pub installed: usize,
    pub cryptographically_rejected: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistorySourceOutboxDrainOutcome {
    pub completed: usize,
    pub expired: usize,
    pub unfinished: usize,
}

/// One holder archive whose archive-lifetime governance closure was fetched
/// through the exact accepted replica coordinate and independently replayed.
#[derive(Clone, Debug)]
pub struct VerifiedOrganizationRecoveryArchive {
    pub item: arkret_sdk::OrganizationRecoveryArchiveListItem,
    pub traversal: garth::VerifiedHistoryTraversal,
}

/// Verified holder archive page. Pagination remains bound to the original
/// typed list query; each item has its own independent traversal closure.
#[derive(Clone, Debug)]
pub struct VerifiedOrganizationRecoveryArchivePage {
    pub items: Vec<VerifiedOrganizationRecoveryArchive>,
    pub cursor: Option<String>,
    pub limited: bool,
}

struct ResponseCapabilityOpener<'a> {
    secure_store: &'a dyn SecureKeyStore,
}

impl garth::HistoryResponseCapabilityOpener for ResponseCapabilityOpener<'_> {
    async fn open_response_capability(
        &self,
        outcome: &arkret_sdk::HistoryKeyRequestCreateOutcome,
    ) -> garth::Result<String> {
        let private_key =
            load_history_request_hpke_private_key(self.secure_store, &outcome.request.request_id)
                .map_err(|error| garth::Error::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    garth::Error::Protocol(
                        "history request HPKE private key is not durably available".to_owned(),
                    )
                })?;
        let receipt = &outcome.request_receipt;
        let context = arkret_sdk::HistoryResponseCapabilitySealContext {
            purpose: arkret_sdk::HistoryResponseCapabilitySealPurpose::Value,
            request_digest: receipt.request_digest.clone(),
            response_capability_commitment: receipt.response_capability_commitment.clone(),
            effective_scope: receipt.effective_scope.clone(),
            release_service_id: receipt.release_service_id.clone(),
            release_service_binding_ref: receipt.release_service_binding_ref.clone(),
            release_service_resolution_ref: receipt.release_service_resolution_ref.clone(),
            release_service_resolution_sequence: receipt.release_service_resolution_sequence,
            release_service_resolution_record_digest: receipt
                .release_service_resolution_record_digest
                .clone(),
            release_service_route_digest: receipt.release_service_route_digest.clone(),
            expires_at: receipt.expires_at,
        };
        arkret_crypto::secret_share::open_history_response_capability(
            &URL_SAFE_NO_PAD.encode(private_key),
            &context,
            &outcome.sealed_history_response_capability,
        )
        .map(|plaintext| plaintext.response_capability_b64u)
        .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

fn history_request_hpke_private_key(request_id: &arkret_sdk::HistoryRequestId) -> String {
    let request = arkret_sdk::canonical::sha256_base64url(request_id.as_str().as_bytes());
    format!("{HISTORY_REQUEST_HPKE_PRIVATE_KEY_PREFIX}.{request}")
}

async fn load_or_create_history_request_hpke_keypair_durable(
    store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
) -> Result<(Vec<u8>, Vec<u8>), crate::secure_key_store::SecureKeyStoreError> {
    static CREATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = CREATE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let key = history_request_hpke_private_key(request_id);
    let private_key = match store.get_secret_bytes(&key)? {
        Some(existing) => existing.as_ref().to_vec(),
        None => {
            let mut generated = [0_u8; 32];
            getrandom::fill(&mut generated).map_err(|error| {
                crate::secure_key_store::SecureKeyStoreError::Backend(format!(
                    "generate history request HPKE private key: {error}"
                ))
            })?;
            store
                .put_secret(
                    &key,
                    &generated,
                    garth::PutSecretOptions {
                        durability: garth::SecretDurability::DurableBeforeReturn,
                        class: garth::SecretClass::MlsSecret,
                    },
                )
                .await?;
            generated.to_vec()
        }
    };
    let scalar: [u8; 32] = private_key.as_slice().try_into().map_err(|_| {
        crate::secure_key_store::SecureKeyStoreError::Backend(
            "history request HPKE private key is not 32 bytes".to_owned(),
        )
    })?;
    let secret = x25519_dalek::StaticSecret::from(scalar);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((private_key, public.as_bytes().to_vec()))
}

fn load_history_request_hpke_private_key(
    store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
) -> Result<Option<Vec<u8>>, crate::secure_key_store::SecureKeyStoreError> {
    store
        .get_secret_bytes(&history_request_hpke_private_key(request_id))
        .map(|bytes| bytes.map(|bytes| bytes.as_ref().to_vec()))
}

struct ReceiptTraversal<'a> {
    api: &'a crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
}

impl garth::ReceiptBoundHistoryTraversal for ReceiptTraversal<'_> {
    async fn acquire_and_verify(
        &self,
        retention: &arkret_sdk::HistoryGovernanceTraversalRetention,
        access: &arkret_sdk::SelfHistoryTraversalAccess,
    ) -> garth::Result<garth::VerifiedHistoryTraversal> {
        let (realm_id, base_basis) = match &retention.traversal_intent {
            arkret_sdk::HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
                effective_scope,
                trusted_history_base_basis,
                ..
            }
            | arkret_sdk::HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
                effective_scope,
                trusted_history_base_basis,
                ..
            } => {
                let realm_id = match effective_scope {
                    arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
                    | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => {
                        realm_id.clone()
                    }
                };
                (realm_id, trusted_history_base_basis)
            }
        };
        let existing = self
            .state_store
            .read()
            .trusted_mls_governance_checkpoint(realm_id.as_str())
            .ok_or_else(|| {
                garth::Error::Protocol(
                    "history traversal has no complete locally verified checkpoint".to_owned(),
                )
            })?;
        let base = arkret_sdk::derive_verified_mls_governance_checkpoint_at_basis(
            &existing,
            base_basis,
            |event, digest_suite, evidence, dependencies| {
                crate::mls::governance_proof::verify_native_agent_history_key(
                    &self.state_store,
                    event,
                    digest_suite,
                    evidence,
                    dependencies,
                )
            },
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let cut = crate::mls::governance_acquisition::resolve_history_governance_cut(
            self.api, retention, access,
        )
        .await
        .map_err(garth::Error::Protocol)?;
        let checkpoint = arkret_sdk::verify_mls_governance_cut(
            &base,
            &cut.target_basis,
            &cut.seals,
            &cut.events,
            &cut.dependencies,
            |event, digest_suite, evidence, dependencies| {
                crate::mls::governance_proof::verify_native_agent_history_key(
                    &self.state_store,
                    event,
                    digest_suite,
                    evidence,
                    dependencies,
                )
            },
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(garth::VerifiedHistoryTraversal { checkpoint })
    }
}

fn runtime(
    state_store: SyncSignal<LocalStateStore>,
) -> garth::HistoryRuntime<crate::state::InksonHistoryRuntimeStore> {
    crate::state::history_runtime(state_store)
}

pub fn accepted_history_request_ids(
    state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<Vec<arkret_sdk::HistoryRequestId>> {
    runtime(state_store)
        .accepted_request_ids()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn http_client(api: &crate::transport::TransportClient) -> anyhow::Result<arkret_sdk::Client> {
    api.sdk_http_client()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrdinaryHumanHistoryRequestPlan {
    pub request_id: arkret_sdk::HistoryRequestId,
    pub effective_scope: arkret_sdk::HistoryEffectiveScope,
    pub requester_authorization_incarnation: arkret_sdk::AuthorizationIncarnation,
    pub requested_ranges: Vec<arkret_sdk::EpochRange>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAgentHistoryRequestPlan {
    pub request_id: arkret_sdk::HistoryRequestId,
    pub effective_scope: arkret_sdk::HistoryEffectiveScope,
    pub requester_agent_id: arkret_sdk::DidCoreId,
    pub requester_agent_verification_method: arkret_sdk::DidUrl,
    pub requester_authorization_incarnation: arkret_sdk::AuthorizationIncarnation,
    pub requested_ranges: Vec<arkret_sdk::EpochRange>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

fn request_trust_bases(
    state_store: SyncSignal<LocalStateStore>,
    scope: &arkret_sdk::HistoryEffectiveScope,
) -> anyhow::Result<(
    arkret_sdk::SealBasis,
    arkret_sdk::SealBasis,
    arkret_sdk::MlsGovernanceVerificationCheckpoint,
)> {
    let checkpoint = state_store
        .read()
        .trusted_mls_governance_checkpoint(scope.realm_id().as_str())
        .ok_or_else(|| anyhow::anyhow!("history request has no durable verified governance pin"))?;
    if &checkpoint.realm_id != scope.realm_id() {
        anyhow::bail!("history request governance pin belongs to another Realm");
    }
    let mut bootstrap_leaves = checkpoint
        .accepted_seals
        .iter()
        .filter(|seal| seal.predecessor_refs.is_empty())
        .map(|seal| seal.id.clone())
        .collect::<Vec<_>>();
    bootstrap_leaves.sort();
    bootstrap_leaves.dedup();
    let trusted_history_base_basis = arkret_sdk::SealBasis {
        leaves: bootstrap_leaves,
    };
    trusted_history_base_basis.validate_protocol_bounds()?;
    checkpoint.basis.validate_protocol_bounds()?;
    Ok((
        trusted_history_base_basis,
        checkpoint.basis.clone(),
        checkpoint,
    ))
}

fn verify_authorization_incarnation_is_retained_join(
    checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
    scope: &arkret_sdk::HistoryEffectiveScope,
    actor_id: &arkret_sdk::DidCoreId,
    incarnation: &arkret_sdk::AuthorizationIncarnation,
) -> anyhow::Result<u64> {
    let group_id =
        arkret_sdk::MlsGroupId::new(scope.canonical_mls_group_id()?).map_err(anyhow::Error::msg)?;
    let join_epoch = arkret_sdk::direct_traversal::derive_history_join_epoch(
        &checkpoint.accepted_events,
        &arkret_sdk::direct_traversal::HistoryJoinEpochSubject {
            mls_group_id: group_id,
            requester_actor_id: actor_id.clone(),
            authorization_incarnation: incarnation.clone(),
        },
    )?;
    match (scope, incarnation) {
        (
            arkret_sdk::HistoryEffectiveScope::Realm { .. },
            arkret_sdk::AuthorizationIncarnation::Realm { .. },
        )
        | (
            arkret_sdk::HistoryEffectiveScope::Circle { .. },
            arkret_sdk::AuthorizationIncarnation::Circle { .. },
        ) => Ok(join_epoch),
        _ => anyhow::bail!("history request scope and authorization incarnation branch differ"),
    }
}

async fn current_ordinary_human_endpoint_authorization(
    http: &arkret_sdk::http_client::Client,
    requester_full_id: &arkret_sdk::DidFullId,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<arkret_sdk::RequesterEndpointAuthorization> {
    let requester_device_authorize_event_id =
        crate::mls::admission::current_requester_device_authorize_event_id(
            http,
            device_id.as_str(),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let keys =
        crate::transport::keys::query_keys(http, requester_full_id.as_str(), device_id.as_str())
            .await?;
    let actor_id = arkret_sdk::project_full_id_to_core_id(requester_full_id)?;
    let generation = keys.device_generations.get(&actor_id).ok_or_else(|| {
        anyhow::anyhow!("history request device generation is absent from the PCR projection")
    })?;
    if generation.device_generation_status != arkret_sdk::DeviceGenerationStatus::Active {
        anyhow::bail!("history request device generation is not active");
    }
    let device = keys
        .device_keys
        .get(&actor_id)
        .and_then(|devices| devices.get(device_id))
        .ok_or_else(|| {
            anyhow::anyhow!("history request device is absent from the PCR projection")
        })?;
    let attested = &device.device_projection_attestation.attestation;
    if attested.device_status != arkret_sdk::DeviceStatus::Active
        || attested.authorized_generation_ref != generation.current_device_generation_ref
        || attested.device_authorize_event_id != requester_device_authorize_event_id
    {
        anyhow::bail!("history request device authorization is not the exact current PCR tuple");
    }
    Ok(arkret_sdk::RequesterEndpointAuthorization::OrdinaryHuman {
        requester_device_id: device_id.clone(),
        requester_device_authorize_event_id,
        requester_device_generation_ref: generation.current_device_generation_ref,
    })
}

/// Author the closed ordinary-human request from durable governance and PCR
/// facts, then persist the immutable pending intent before transport. An exact
/// request-id retry reuses the already durable request, including both bases,
/// ranges, endpoint authorization and recipient key.
pub async fn author_and_create_ordinary_human_request(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    requester_full_id: &arkret_sdk::DidFullId,
    device_id: &arkret_sdk::DeviceId,
    plan: OrdinaryHumanHistoryRequestPlan,
) -> anyhow::Result<(arkret_sdk::HistoryKeyRequestCreateOutcome, u64)> {
    let requester_actor_id = arkret_sdk::project_full_id_to_core_id(requester_full_id)?;
    if requester_actor_id != authority.principal_id {
        anyhow::bail!("history request actor differs from the explicit account authority");
    }
    let (_, _, checkpoint) = request_trust_bases(state_store, &plan.effective_scope)?;
    let join_epoch = verify_authorization_incarnation_is_retained_join(
        &checkpoint,
        &plan.effective_scope,
        &requester_actor_id,
        &plan.requester_authorization_incarnation,
    )?;
    if let Ok(durable) = runtime(state_store).durable_request(&plan.request_id) {
        if durable.request.effective_scope != plan.effective_scope
            || durable.request.requested_ranges != plan.requested_ranges
            || durable.request.expires_at != plan.expires_at
            || durable.request.requester_actor_id != requester_actor_id
            || durable.request.requester_authorization_incarnation
                != plan.requester_authorization_incarnation
        {
            anyhow::bail!("history request id is already bound to another durable intent");
        }
        let accepted =
            create_or_resume_authored_request(state_store, api, secure_store, durable.request)
                .await?;
        return Ok((accepted, join_epoch));
    }

    let http = http_client(api)?;
    let endpoint_authorization =
        current_ordinary_human_endpoint_authorization(&http, requester_full_id, device_id).await?;
    let (trusted_history_base_basis, trusted_current_basis, _) =
        request_trust_bases(state_store, &plan.effective_scope)?;
    let (_, public_key) =
        load_or_create_history_request_hpke_keypair_durable(secure_store, &plan.request_id).await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("history request has no active endpoint signer"))?;
    if signer.device_id() != Some(device_id.as_str()) {
        anyhow::bail!("history request signer is not bound to the explicit current device");
    }
    let verification_method = signer.verification_method_for_principal(requester_full_id)?;
    let request = arkret_sdk::HistoryKeyRequest::build_signed_proof(
        verification_method.clone(),
        crate::clock::now_utc(),
        |requester_proof| arkret_sdk::HistoryKeyRequest {
            request_id: plan.request_id.clone(),
            kind: arkret_sdk::HistoryKeyRequestKind::Value,
            effective_scope: plan.effective_scope.clone(),
            requester_actor_id: requester_actor_id.clone(),
            requester_sender_domain: device_id.as_str().to_owned(),
            requester_author_profile: arkret_sdk::AuthorProfile::OrdinaryHuman,
            requester_endpoint_authorization: endpoint_authorization.clone(),
            requester_authorization_incarnation: plan.requester_authorization_incarnation.clone(),
            trusted_history_base_basis: trusted_history_base_basis.clone(),
            trusted_current_basis: trusted_current_basis.clone(),
            requested_ranges: plan.requested_ranges.clone(),
            recipient_hpke_public_key: URL_SAFE_NO_PAD.encode(&public_key),
            expires_at: plan.expires_at,
            requester_proof,
        },
        |bytes| {
            signer
                .detached_jws_over_payload_with_kid(verification_method.as_str(), bytes)
                .map_err(|error| arkret_sdk::WireError::Protocol(error.to_string()))
        },
    )?;
    request.validate()?;
    let accepted =
        create_or_resume_authored_request(state_store, api, secure_store, request).await?;
    Ok((accepted, join_epoch))
}

/// Author a Native Agent history request from a freshly verified current
/// Agent signer evidence query. The Agent id, runtime method and exact
/// agent-key-authorize Event are taken from that closed verification result;
/// no account session or device default participates.
pub async fn author_and_create_native_agent_request(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    plan: NativeAgentHistoryRequestPlan,
) -> anyhow::Result<(arkret_sdk::HistoryKeyRequestCreateOutcome, u64)> {
    let (_, _, checkpoint) = request_trust_bases(state_store, &plan.effective_scope)?;
    let join_epoch = verify_authorization_incarnation_is_retained_join(
        &checkpoint,
        &plan.effective_scope,
        &plan.requester_agent_id,
        &plan.requester_authorization_incarnation,
    )?;
    if let Ok(durable) = runtime(state_store).durable_request(&plan.request_id) {
        let expected_endpoint = match &durable.request.requester_endpoint_authorization {
            arkret_sdk::RequesterEndpointAuthorization::NativeAgent {
                requester_agent_id,
                requester_agent_verification_method,
                ..
            } => {
                requester_agent_id == &plan.requester_agent_id
                    && requester_agent_verification_method
                        == &plan.requester_agent_verification_method
            }
            _ => false,
        };
        if durable.request.effective_scope != plan.effective_scope
            || durable.request.requested_ranges != plan.requested_ranges
            || durable.request.expires_at != plan.expires_at
            || durable.request.requester_actor_id != plan.requester_agent_id
            || durable.request.requester_authorization_incarnation
                != plan.requester_authorization_incarnation
            || !expected_endpoint
        {
            anyhow::bail!("history request id is already bound to another durable intent");
        }
        let accepted =
            create_or_resume_authored_request(state_store, api, secure_store, durable.request)
                .await?;
        return Ok((accepted, join_epoch));
    }

    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("history request has no active Agent endpoint signer"))?;
    let signer_full_id = arkret_sdk::DidFullId::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_full_id_to_core_id(&signer_full_id)? != plan.requester_agent_id
        || signer.verification_method() != plan.requester_agent_verification_method.as_str()
    {
        anyhow::bail!("history request signer differs from the explicit Agent endpoint");
    }
    let (trusted_history_base_basis, trusted_current_basis, _) =
        request_trust_bases(state_store, &plan.effective_scope)?;
    let (_, public_key) =
        load_or_create_history_request_hpke_keypair_durable(secure_store, &plan.request_id).await?;
    let authorization_query_digest = arkret_sdk::Hash::new(
        arkret_sdk::canonical::canonical_sha256(&serde_json::json!({
            "request_id": &plan.request_id,
            "effective_scope": &plan.effective_scope,
            "requester_agent_id": &plan.requester_agent_id,
            "requester_agent_verification_method": &plan.requester_agent_verification_method,
            "requester_authorization_incarnation": &plan.requester_authorization_incarnation,
            "trusted_history_base_basis": &trusted_history_base_basis,
            "trusted_current_basis": &trusted_current_basis,
            "requested_ranges": &plan.requested_ranges,
            "recipient_hpke_public_key": URL_SAFE_NO_PAD.encode(&public_key),
            "expires_at": plan.expires_at,
        }))?,
    )?;
    let http = http_client(api)?;
    let requester_agent_key_authorize_event_id =
        crate::identity::agent_signer_evidence::resolve_current_history_request_authorization(
            &http,
            plan.effective_scope.realm_id(),
            &plan.requester_agent_id,
            &plan.requester_agent_verification_method,
            &authorization_query_digest,
        )
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "history request Agent endpoint has no fully verified current authorization"
            )
        })?;
    let verification_method = plan.requester_agent_verification_method.clone();
    let request = arkret_sdk::HistoryKeyRequest::build_signed_proof(
        verification_method.clone(),
        crate::clock::now_utc(),
        |requester_proof| arkret_sdk::HistoryKeyRequest {
            request_id: plan.request_id.clone(),
            kind: arkret_sdk::HistoryKeyRequestKind::Value,
            effective_scope: plan.effective_scope.clone(),
            requester_actor_id: plan.requester_agent_id.clone(),
            requester_sender_domain: plan.requester_agent_id.as_str().to_owned(),
            requester_author_profile: arkret_sdk::AuthorProfile::NativeAgent,
            requester_endpoint_authorization:
                arkret_sdk::RequesterEndpointAuthorization::NativeAgent {
                    requester_agent_id: plan.requester_agent_id.clone(),
                    requester_agent_verification_method: verification_method.clone(),
                    requester_agent_key_authorize_event_id: requester_agent_key_authorize_event_id
                        .clone(),
                },
            requester_authorization_incarnation: plan.requester_authorization_incarnation.clone(),
            trusted_history_base_basis: trusted_history_base_basis.clone(),
            trusted_current_basis: trusted_current_basis.clone(),
            requested_ranges: plan.requested_ranges.clone(),
            recipient_hpke_public_key: URL_SAFE_NO_PAD.encode(&public_key),
            expires_at: plan.expires_at,
            requester_proof,
        },
        |bytes| {
            signer
                .detached_jws_over_payload_with_kid(verification_method.as_str(), bytes)
                .map_err(|error| arkret_sdk::WireError::Protocol(error.to_string()))
        },
    )?;
    request.validate()?;
    let accepted =
        create_or_resume_authored_request(state_store, api, secure_store, request).await?;
    Ok((accepted, join_epoch))
}

async fn create_or_resume_authored_request(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request: arkret_sdk::HistoryKeyRequest,
) -> anyhow::Result<arkret_sdk::HistoryKeyRequestCreateOutcome> {
    let (_, public_key) =
        load_or_create_history_request_hpke_keypair_durable(secure_store, &request.request_id)
            .await?;
    if URL_SAFE_NO_PAD.encode(public_key) != request.recipient_hpke_public_key {
        anyhow::bail!(
            "history request recipient HPKE public key differs from its durable request private key"
        );
    }
    let http = http_client(api)?;
    runtime(state_store)
        .create_or_resume_request(
            &http,
            &ResponseCapabilityOpener { secure_store },
            secure_store,
            request,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Publish a complete source attempt only after every canonical signed record
/// is durable in the secure content-addressed blob store. The Garth attempt
/// row is the atomic ready marker; callers may safely crash after this returns.
pub async fn stage_member_source_attempt(
    state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn SecureKeyStore,
    bundle: garth::HistorySourceAttemptBundle,
) -> anyhow::Result<garth::HistorySourceAttemptIdentity> {
    if bundle.manifest.route() != garth::HistorySourceRoute::Direct
        || bundle
            .chunks
            .iter()
            .any(|record| record.route() != garth::HistorySourceRoute::Direct)
    {
        anyhow::bail!("Inkson member source attempts must use the authenticated self-send route");
    }
    let blobs = crate::state::InksonHistorySourceBlobStore::new(secure_store);
    crate::state::history_source_outbox(state_store)
        .stage_attempt(&blobs, bundle)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Resume every durable ready source attempt. Exact signed bytes are loaded
/// from the content-addressed secure store; neither proofs nor relay
/// attestations are reconstructed during retry.
pub async fn drain_source_outbox(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<HistorySourceOutboxDrainOutcome> {
    let http = http_client(api)?;
    let blobs = crate::state::InksonHistorySourceBlobStore::new(secure_store);
    let outbox = crate::state::history_source_outbox(state_store);
    let mut outcome = HistorySourceOutboxDrainOutcome::default();
    let mut first_error = None;
    for identity in outbox
        .ready_attempt_identities(garth::HistorySourceRoute::Direct)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        match outbox.replay_attempt(&http, &blobs, &identity, now).await {
            Ok(attempt) => match attempt.status {
                garth::HistorySourceAttemptStatus::Completed => outcome.completed += 1,
                garth::HistorySourceAttemptStatus::Expired => outcome.expired += 1,
                garth::HistorySourceAttemptStatus::Unfinished => outcome.unfinished += 1,
            },
            Err(error) => {
                outcome.unfinished += 1;
                tracing::warn!(
                    request_id = %identity.request_id,
                    manifest_response_id = %identity.manifest_response_id,
                    %error,
                    "history source outbox attempt remains pending"
                );
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!(error.to_string()));
                }
            }
        }
    }
    first_error.map_or(Ok(outcome), Err)
}

pub async fn list_requests(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    query: &arkret_sdk::HistoryKeyRequestListQuery,
) -> anyhow::Result<arkret_sdk::HistoryKeyRequestListOutcome> {
    let http = http_client(api)?;
    runtime(state_store)
        .list_requests(&http, query)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Discover the scope-private request projection exposed to a current member
/// endpoint (including byte-identical peer replicas). Re-running this after a
/// join or delivery rebind is intentional: the service projection is the
/// authoritative discovery surface and request ids make repeated pages safe.
pub async fn discover_member_request_replicas(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    realm_id: &str,
    circle_id: Option<&str>,
    cursor: Option<String>,
    limit: Option<u8>,
) -> anyhow::Result<arkret_sdk::HistoryKeyRequestListOutcome> {
    let query = arkret_sdk::HistoryKeyRequestListQuery {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        circle_id: circle_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| arkret_sdk::CircleId::new(value.to_owned()))
            .transpose()?,
        cursor,
        limit,
    };
    list_requests(state_store, api, &query).await
}

/// Discover Recovery Key archives through the dedicated holder route. This is
/// deliberately separate from member request-list discovery and its bearer
/// response stream; the closed query carries the accepted key evidence and
/// holder basis required by the Recovery Key protocol.
pub async fn discover_organization_recovery_archives(
    api: &crate::transport::TransportClient,
    query: &arkret_sdk::OrganizationRecoveryArchiveListQuery,
) -> anyhow::Result<arkret_sdk::OrganizationRecoveryArchiveListOutcome> {
    let http = http_client(api)?;
    let outcome = http
        .organization_recovery_archive_list(query)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    outcome
        .validate_for_query(query)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(outcome)
}

pub fn organization_recovery_archive_traversal_access(
    item: &arkret_sdk::OrganizationRecoveryArchiveListItem,
) -> arkret_sdk::SelfHistoryTraversalAccess {
    arkret_sdk::SelfHistoryTraversalAccess::ArchiveReplica {
        archive_replica_digest: item.archive_replica_digest.clone(),
    }
}

/// Discover and independently replay every RRK holder archive in one page.
///
/// The list item's exact `archive_replica_digest` is copied into the closed
/// self-traversal access branch. No archive digest, intent digest or current
/// governance coordinate is accepted as a substitute.
pub async fn discover_and_verify_organization_recovery_archives(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    query: &arkret_sdk::OrganizationRecoveryArchiveListQuery,
) -> anyhow::Result<VerifiedOrganizationRecoveryArchivePage> {
    let outcome = discover_organization_recovery_archives(api, query).await?;
    let mut verified = Vec::with_capacity(outcome.items.len());
    for item in outcome.items {
        let access = organization_recovery_archive_traversal_access(&item);
        let traversal = garth::ReceiptBoundHistoryTraversal::acquire_and_verify(
            &ReceiptTraversal { api, state_store },
            &item.history_traversal_retention,
            &access,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        verified.push(VerifiedOrganizationRecoveryArchive { item, traversal });
    }
    Ok(VerifiedOrganizationRecoveryArchivePage {
        items: verified,
        cursor: outcome.cursor,
        limited: outcome.limited,
    })
}

pub async fn acquire_response_page(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
) -> anyhow::Result<arkret_sdk::HistoryKeyResponseListOutcome> {
    let http = http_client(api)?;
    runtime(state_store)
        .acquire_response_page(&http, secure_store, request_id, limit)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Verify and install one durable response_stream page into the external candidate
/// ledger. Public DID/service keys are verified entirely by the SDK from the
/// retained dependency closure. The external callback is restricted to the
/// Native Agent and minimal-metadata MLS branches with explicit typed state
/// anchors.
pub async fn verify_and_install_response_page<VerifyExternalSourceKey>(
    mut state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
    now: chrono::DateTime<chrono::Utc>,
    verify_external_source_key: VerifyExternalSourceKey,
) -> anyhow::Result<HistoryResponsePageInstallOutcome>
where
    VerifyExternalSourceKey: Fn(
        arkret_sdk::HistorySourceProofExternalVerificationRequest<'_>,
    ) -> std::result::Result<
        arkret_sdk::signatures::proof::PublicKeyMaterial,
        arkret_sdk::WireError,
    >,
{
    let traversal = acquire_and_verify_traversal(state_store, api, request_id).await?;
    let page = acquire_response_page(state_store, api, secure_store, request_id, limit).await?;
    let runtime = runtime(state_store);
    let durable = runtime
        .durable_request(request_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let accepted = durable.accepted.ok_or_else(|| {
        anyhow::anyhow!(
            "history request is not durably accepted before response stream installation"
        )
    })?;
    let private_key = load_history_request_hpke_private_key(secure_store, request_id)?
        .ok_or_else(|| anyhow::anyhow!("history recipient HPKE private key is unavailable"))?;
    let private_key_b64u = URL_SAFE_NO_PAD.encode(private_key);
    let request_receipt_digest = accepted.request_receipt.request_receipt_digest()?;
    let realm_id = match &accepted.request.effective_scope {
        arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
        | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id.clone(),
    };
    let signer_dependencies =
        crate::mls::governance_acquisition::resolve_history_response_signer_dependencies(
            api,
            &realm_id,
            &request_receipt_digest,
            page.ack_entries.iter().filter_map(|entry| match entry {
                arkret_sdk::HistoryResponsePageEntry::Record { record } => {
                    Some(record.source_record.source_signer_evidence_digest.clone())
                }
                arkret_sdk::HistoryResponsePageEntry::Lost { .. } => None,
            }),
            page.ack_entries.iter().map(|entry| match entry {
                arkret_sdk::HistoryResponsePageEntry::Record { record } => {
                    record.release_service_signer_evidence_digest.clone()
                }
                arkret_sdk::HistoryResponsePageEntry::Lost { lost_record } => {
                    lost_record.release_service_signer_evidence_digest.clone()
                }
            }),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let mut outcome = HistoryResponsePageInstallOutcome::default();

    for entry in &page.ack_entries {
        let arkret_sdk::HistoryResponsePageEntry::Record { record } = entry else {
            let arkret_sdk::HistoryResponsePageEntry::Lost { lost_record } = entry else {
                unreachable!("history response stream page entry is a closed union")
            };
            let lost_dependencies = arkret_sdk::history_response_lost_signer_dependency_closure(
                lost_record,
                &signer_dependencies,
            )?;
            arkret_sdk::verify_history_response_lost_record(
                &accepted,
                lost_record,
                &lost_dependencies,
            )?;
            runtime
                .record_response_disposition(
                    request_id,
                    arkret_sdk::HistoryResponseAckEntry::Lost {
                        sequence: lost_record.sequence,
                        response_id: lost_record.response_id.clone(),
                        lost_record_digest: lost_record.record_digest.clone(),
                        status: arkret_sdk::HistoryResponseLostStatus::Value,
                    },
                )
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            continue;
        };
        let record_dependencies = (|| -> anyhow::Result<Vec<_>> {
            let partition = arkret_sdk::history_response_record_signer_dependency_closure(
                record,
                &signer_dependencies,
            )?;
            let mut record_dependencies = std::collections::BTreeMap::new();
            for dependency in partition
                .source_signer_dependencies
                .into_iter()
                .chain(partition.release_service_signer_dependencies)
            {
                let key = arkret_sdk::canonical::canonical_json_bytes(dependency.selector())?;
                if let Some(previous) = record_dependencies.insert(key, dependency.clone())
                    && previous != dependency
                {
                    return Err(anyhow::anyhow!(
                        "response stream signer dependency selector resolved to conflicting values"
                    ));
                }
            }
            Ok(record_dependencies.into_values().collect())
        })();
        let record_dependencies = match record_dependencies {
            Ok(dependencies) => dependencies,
            Err(error) => {
                tracing::warn!(
                    sequence = record.sequence,
                    %error,
                    "history response stream signer dependency closure was cryptographically rejected"
                );
                runtime
                    .record_response_disposition(
                        request_id,
                        arkret_sdk::HistoryResponseAckEntry::Record {
                            sequence: record.sequence,
                            response_id: record.source_record.response_id.clone(),
                            record_digest: record.record_digest.clone(),
                            status:
                                arkret_sdk::HistoryResponseRecordStatus::CryptographicallyRejected,
                        },
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                outcome.cryptographically_rejected += 1;
                continue;
            }
        };
        let manifest = match &record.source_record.content {
            arkret_sdk::HistoryKeyResponseContent::Chunk(chunk) => runtime
                .verified_manifest(request_id, &chunk.manifest_digest)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .map(|manifest| arkret_sdk::VerifiedHistoryManifest {
                    response_id: manifest.response_id,
                    source_actor_id: manifest.source_actor_id,
                    source_sender_domain: manifest.source_sender_domain,
                    manifest_digest: manifest.manifest_digest,
                    manifest_admission_digest: manifest.manifest_admission_digest,
                    chunks: manifest.chunks,
                }),
            arkret_sdk::HistoryKeyResponseContent::Manifest(_) => None,
        };
        let verified = match arkret_sdk::verify_history_response_record(
            &accepted,
            record,
            &traversal.checkpoint,
            manifest.as_ref(),
            &record_dependencies,
            now,
            &verify_external_source_key,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                tracing::warn!(
                    sequence = record.sequence,
                    %error,
                    "history response stream record was cryptographically rejected"
                );
                runtime
                    .record_response_disposition(
                        request_id,
                        arkret_sdk::HistoryResponseAckEntry::Record {
                            sequence: record.sequence,
                            response_id: record.source_record.response_id.clone(),
                            record_digest: record.record_digest.clone(),
                            status:
                                arkret_sdk::HistoryResponseRecordStatus::CryptographicallyRejected,
                        },
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                outcome.cryptographically_rejected += 1;
                continue;
            }
        };
        match verified {
            arkret_sdk::VerifiedHistoryResponseRecord::Manifest { manifest, .. } => {
                runtime
                    .install_verified_manifest(
                        request_id,
                        garth::DurableVerifiedHistoryManifest {
                            response_id: manifest.response_id,
                            source_actor_id: manifest.source_actor_id,
                            source_sender_domain: manifest.source_sender_domain,
                            manifest_digest: manifest.manifest_digest,
                            manifest_admission_digest: manifest.manifest_admission_digest,
                            chunks: manifest.chunks,
                        },
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            }
            arkret_sdk::VerifiedHistoryResponseRecord::Chunk { chunk, .. } => {
                let prepared = (|| -> anyhow::Result<Vec<_>> {
                    let plaintext = arkret_crypto::secret_share::open_history_secret_chunk(
                        &private_key_b64u,
                        &chunk.seal_context,
                        &chunk.sealed_chunk,
                    )?;
                    plaintext.validate()?;
                    if plaintext.secret_range.from_epoch != chunk.covered_epoch_range.from_epoch
                        || plaintext.secret_range.to_epoch != chunk.covered_epoch_range.to_epoch
                    {
                        return Err(anyhow::anyhow!(
                            "history chunk plaintext range differs from its signed descriptor"
                        ));
                    }
                    let suites = arkret_sdk::winning_history_epoch_suites_from_verified_checkpoint(
                        &traversal.checkpoint,
                        &accepted.request.effective_scope,
                        &accepted.request.effective_scope.canonical_mls_group_id()?,
                        std::slice::from_ref(&chunk.covered_epoch_range),
                    )?;
                    let secret_bytes = arkret_sdk::base64url_decode(
                        plaintext.secret_range.secrets_b64u.as_bytes(),
                    )?;
                    let expected_len = suites.iter().try_fold(0_usize, |total, suite| {
                        total
                            .checked_add(usize::from(suite.kdf_nh))
                            .ok_or_else(|| anyhow::anyhow!("history secret range length overflow"))
                    })?;
                    if secret_bytes.len() != expected_len {
                        return Err(anyhow::anyhow!(
                            "history secret range byte length does not equal winning MLS KDF.Nh sum"
                        ));
                    }
                    let source_record_digest = record.source_record.source_record_digest()?;
                    let mut offset = 0_usize;
                    let mut candidates = Vec::with_capacity(suites.len());
                    for suite in suites {
                        let next = offset + usize::from(suite.kdf_nh);
                        let secret = secret_bytes[offset..next].to_vec();
                        let material_key = arkret_sdk::HistoryCandidateMaterialKey {
                            effective_scope: accepted.request.effective_scope.clone(),
                            mls_group_id: accepted
                                .request
                                .effective_scope
                                .canonical_mls_group_id()?,
                            epoch: suite.epoch,
                            candidate_digest: arkret_sdk::Hash::new(
                                arkret_sdk::canonical::sha256_digest(&secret),
                            )?,
                        };
                        let attribution =
                            arkret_sdk::HistoryCandidateOriginAttribution::ResponseSender {
                                material_key: material_key.clone(),
                                origin_quota_domain: arkret_sdk::ResponseSenderQuotaDomain {
                                    source_sender_domain: chunk.source_sender_domain.clone(),
                                },
                                origin_ref: arkret_sdk::ResponseSenderOriginRef {
                                    response_id: chunk.response_id.clone(),
                                    source_record_digest: source_record_digest.clone(),
                                },
                                first_observed_at: now,
                            };
                        candidates.push((material_key, secret, attribution, suite.cipher_suite));
                        offset = next;
                    }
                    Ok(candidates)
                })();
                let candidates = match prepared {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        tracing::warn!(
                            sequence = record.sequence,
                            %error,
                            "history response stream chunk payload was cryptographically rejected"
                        );
                        runtime
                            .record_response_disposition(
                                request_id,
                                arkret_sdk::HistoryResponseAckEntry::Record {
                                    sequence: record.sequence,
                                    response_id: record.source_record.response_id.clone(),
                                    record_digest: record.record_digest.clone(),
                                    status: arkret_sdk::HistoryResponseRecordStatus::CryptographicallyRejected,
                                },
                            )
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                        outcome.cryptographically_rejected += 1;
                        continue;
                    }
                };
                let history_scope = match &accepted.request.effective_scope {
                    arkret_sdk::HistoryEffectiveScope::Realm { realm_id } => {
                        arkret_sdk::ScopeRef::Realm {
                            realm_id: realm_id.clone(),
                        }
                    }
                    arkret_sdk::HistoryEffectiveScope::Circle {
                        realm_id,
                        circle_id,
                    } => arkret_sdk::ScopeRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                };
                for (material_key, secret, attribution, cipher_suite) in candidates {
                    let mut state = state_store.write();
                    state
                        .record_history_epoch_cipher_suite(
                            &history_scope,
                            &accepted.request.effective_scope.canonical_mls_group_id()?,
                            material_key.epoch,
                            &cipher_suite,
                        )
                        .map_err(anyhow::Error::msg)?;
                    state
                        .receive_history_candidate(secure_store, &secret, attribution, now)
                        .await?;
                }
            }
        }
        runtime
            .record_response_disposition(
                request_id,
                arkret_sdk::HistoryResponseAckEntry::Record {
                    sequence: record.sequence,
                    response_id: record.source_record.response_id.clone(),
                    record_digest: record.record_digest.clone(),
                    status: arkret_sdk::HistoryResponseRecordStatus::Installed,
                },
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        outcome.installed += 1;
    }
    acknowledge_ready_page(state_store, api, secure_store, request_id).await?;
    Ok(outcome)
}

fn verify_history_external_source_key(
    state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
    request: arkret_sdk::HistorySourceProofExternalVerificationRequest<'_>,
) -> Result<arkret_sdk::signatures::proof::PublicKeyMaterial, arkret_sdk::WireError> {
    match request {
        arkret_sdk::HistorySourceProofExternalVerificationRequest::NativeAgent {
            source_record,
            signer_evidence,
            dependencies,
        } => arkret_sdk::verify_native_agent_history_source_key(
            source_record,
            signer_evidence,
            dependencies,
            |request| {
                crate::mls::governance_proof::verify_native_agent_external_trust(
                    &state_store,
                    request,
                )
            },
        ),
        arkret_sdk::HistorySourceProofExternalVerificationRequest::MinimalMetadata {
            source_record,
            signer_evidence,
            verified_checkpoint,
        } => {
            let realm_id = match &signer_evidence.effective_scope {
                arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
                | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
            };
            let local = state_store
                .read()
                .locally_authenticated_identity_link(
                    realm_id,
                    &signer_evidence.mls_group_id,
                    signer_evidence.epoch,
                    signer_evidence.leaf_index,
                )
                .ok_or_else(|| {
                    arkret_sdk::WireError::Protocol(
                        "minimal-metadata history source has no locally received IdentityLink"
                            .to_owned(),
                    )
                })?;
            let identity_link_bytes = arkret_sdk::base64url_decode(
                local.identity_link_canonical_bytes_b64u.as_str().as_bytes(),
            )?;
            let leaf_node_bytes = arkret_sdk::base64url_decode(
                local.leaf_node_canonical_bytes_b64u.as_str().as_bytes(),
            )?;
            if local.identity_link_digest
                != arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
                    &identity_link_bytes,
                ))?
                || local.leaf_node_digest
                    != arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(
                        &leaf_node_bytes,
                    ))?
                || local.leaf_node_digest != signer_evidence.leaf_node_digest
                || local.winning_group_state_ref
                    != signer_evidence.winning_group_state_transition_ref
            {
                return Err(arkret_sdk::WireError::Protocol(
                    "minimal-metadata local IdentityLink cache is corrupt or mismatched".to_owned(),
                ));
            }
            let effective_scope = match &signer_evidence.effective_scope {
                arkret_sdk::HistoryEffectiveScope::Realm { realm_id } => {
                    arkret_sdk::ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    }
                }
                arkret_sdk::HistoryEffectiveScope::Circle {
                    realm_id,
                    circle_id,
                } => arkret_sdk::ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
            };
            let winning_group_state = crate::mls::runtime::minimal_metadata_author_view_for_scope(
                &state_store.read(),
                secure_store,
                authority,
                device_id,
                &effective_scope,
                &signer_evidence.mls_group_id,
                signer_evidence.epoch,
                signer_evidence.winning_group_state_transition_ref.as_str(),
            )
            .ok_or_else(|| {
                arkret_sdk::WireError::Protocol(
                    "minimal-metadata history source has no local winning MLS state".to_owned(),
                )
            })?;
            arkret_sdk::verify_minimal_metadata_history_source_local_state(
                source_record,
                signer_evidence,
                verified_checkpoint,
                &local.identity_link,
                &identity_link_bytes,
                &winning_group_state,
            )
        }
    }
}

/// Production response stream installer with the only supported external trust
/// boundary wired to Inkson's durable Native Agent and MLS state.
#[allow(clippy::too_many_arguments)]
pub async fn verify_and_install_response_page_from_local_state(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<HistoryResponsePageInstallOutcome> {
    verify_and_install_response_page(
        state_store,
        api,
        secure_store,
        request_id,
        limit,
        now,
        |request| {
            verify_history_external_source_key(
                state_store,
                secure_store,
                authority,
                device_id,
                request,
            )
        },
    )
    .await
}

pub async fn record_response_disposition(
    state_store: SyncSignal<LocalStateStore>,
    request_id: &arkret_sdk::HistoryRequestId,
    disposition: arkret_sdk::HistoryResponseAckEntry,
) -> anyhow::Result<()> {
    runtime(state_store)
        .record_response_disposition(request_id, disposition)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub async fn acknowledge_ready_page(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
) -> anyhow::Result<arkret_sdk::HistoryKeyResponseAckOutcome> {
    let http = http_client(api)?;
    runtime(state_store)
        .acknowledge_ready_page(&http, secure_store, request_id)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub async fn acquire_and_verify_traversal(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    request_id: &arkret_sdk::HistoryRequestId,
) -> anyhow::Result<garth::VerifiedHistoryTraversal> {
    runtime(state_store)
        .acquire_receipt_bound_traversal(&ReceiptTraversal { api, state_store }, request_id)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrk_holder_traversal_uses_the_exact_list_replica_digest() {
        let fixture =
            arkret_schema::embedded_json_artifact("fixtures/history-key-recovery-fixture.json")
                .unwrap();
        let outcome: arkret_sdk::OrganizationRecoveryArchiveListOutcome =
            serde_json::from_value(
                fixture["organization_recovery_archive_durable_before_gc_kat"]
                    ["barrier_resolve_outcome"]
                    .clone(),
            )
            .unwrap();
        let item = &outcome.items[0];

        assert_eq!(
            organization_recovery_archive_traversal_access(item),
            arkret_sdk::SelfHistoryTraversalAccess::ArchiveReplica {
                archive_replica_digest: item.archive_replica_digest.clone(),
            }
        );
    }

    #[tokio::test]
    async fn history_request_hpke_keys_are_durable_and_request_scoped() {
        let store = crate::secure_key_store::MemorySecureKeyStore::new();
        let first = arkret_sdk::HistoryRequestId::new(
            "ak:history_request:01964137-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap();
        let second = arkret_sdk::HistoryRequestId::new(
            "ak:history_request:01964137-0000-7000-8000-000000000002".to_owned(),
        )
        .unwrap();

        let first_pair = load_or_create_history_request_hpke_keypair_durable(&store, &first)
            .await
            .unwrap();
        let first_retry = load_or_create_history_request_hpke_keypair_durable(&store, &first)
            .await
            .unwrap();
        let second_pair = load_or_create_history_request_hpke_keypair_durable(&store, &second)
            .await
            .unwrap();

        assert_eq!(first_pair, first_retry);
        assert_ne!(first_pair, second_pair);
        assert_eq!(
            load_history_request_hpke_private_key(&store, &first)
                .unwrap()
                .unwrap(),
            first_pair.0
        );
    }
}
