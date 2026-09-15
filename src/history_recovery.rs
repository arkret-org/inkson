use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garth::history_runtime::{
    canonical_ranges_for_epochs, live_attempt_covers_epoch, ranges_cover,
};

use crate::runtime::input::StateStoreHandle;
use crate::secure_key_store::SecureKeyStore;

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
    pub permanently_rejected: usize,
    pub unfinished: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryRecoveryConvergenceOutcome {
    pub requests_created_or_resumed: usize,
    pub source_attempts_staged: usize,
    pub source_attempts_completed: usize,
    pub response_records_installed: usize,
    pub pending_errors: usize,
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
            release_id: receipt.release_id.clone(),
            release_service_binding_ref: receipt.release_service_binding_ref.clone(),
            release_service_resolution_ref: receipt.release_service_resolution_ref.clone(),
            release_service_resolution_digest: receipt.release_service_resolution_digest.clone(),
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
    let private_key = match load_history_request_hpke_private_key(store, request_id)? {
        Some(existing) => existing,
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
                    arkret_sdk::base64url_encode(generated).as_bytes(),
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
        .get_secret_bytes(&history_request_hpke_private_key(request_id))?
        .map(|bytes| {
            let decoded = arkret_sdk::base64url_decode(bytes.as_ref()).map_err(|_| {
                crate::secure_key_store::SecureKeyStoreError::Backend(
                    "history request HPKE private key is not canonical base64url".to_owned(),
                )
            })?;
            if decoded.len() != 32
                || arkret_sdk::base64url_encode(&decoded).as_bytes() != bytes.as_ref()
            {
                return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "history request HPKE private key must encode exactly 32 bytes".to_owned(),
                ));
            }
            Ok(decoded)
        })
        .transpose()
}

fn runtime(
    state_store: &StateStoreHandle,
) -> garth::HistoryRuntime<crate::state::InksonHistoryRuntimeStore> {
    crate::state::history_runtime(state_store)
}

pub fn accepted_history_request_ids(
    state_store: &StateStoreHandle,
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

async fn current_history_authority(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    authority: &arkret_sdk::AccountId,
    scope: &arkret_sdk::HistoryEffectiveScope,
    actor: &arkret_sdk::ActorId,
) -> anyhow::Result<arkret_sdk::HistoryAuthorityOutcome> {
    let epoch = crate::identity::device_directory::cache_epoch();
    let observed = state_store.read(|store| {
        store
            .seal_view_for_realm(scope.realm_id().as_str())
            .frontier
            .clone()
    });
    let http = http_client(api)?;
    let view = http
        .seals_frontier(scope.realm_id().clone())
        .await?
        .frontier;
    let query = arkret_sdk::HistoryAuthorityRequestBody {
        effective_scope: scope.clone(),
        actor_id: actor.clone(),
        seal_basis: view.seal_basis,
    };
    let outcome = http.history_authority(&query).await?;
    outcome.validate_for_account(&query, authority)?;
    anyhow::ensure!(
        epoch == crate::identity::device_directory::cache_epoch(),
        "account session changed during history authority query"
    );
    anyhow::ensure!(
        state_store.read(|store| store
            .seal_view_for_realm(scope.realm_id().as_str())
            .frontier
            == observed),
        "observed history frontier changed during authority query"
    );
    Ok(outcome)
}

async fn current_ordinary_human_endpoint_authorization(
    http: &arkret_sdk::http_client::Client,
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<arkret_sdk::RequesterEndpointAuthorization> {
    let requester_device_authorize_event_id =
        crate::mls::admission::current_requester_device_authorize_event_id(
            http,
            device_id.as_str(),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let keys = crate::transport::keys::query_keys(http, account_id, device_id.as_str()).await?;
    let generation = keys.generation_for(account_id).ok_or_else(|| {
        anyhow::anyhow!("history request device generation is absent from the PCR projection")
    })?;
    if generation.device_generation_status != arkret_sdk::DeviceGenerationStatus::Active {
        anyhow::bail!("history request device generation is not active");
    }
    let device = keys
        .devices_for(account_id)
        .and_then(|devices| devices.get(device_id))
        .ok_or_else(|| {
            anyhow::anyhow!("history request device is absent from the PCR projection")
        })?;
    // The row was read at the exact `(account_id, device_id)` selectors; the
    // projection itself carries no account/device identity to re-check.
    let attested = crate::identity::device_directory::validate_self_device_row(device)?;
    let now = chrono::Utc::now();
    if !crate::identity::device_directory::projection_observation_is_fresh(attested, now)
        || !crate::identity::device_directory::projection_authorization_window_contains(
            attested, now,
        )
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

/// Author the closed ordinary-human intent from current Station authority and
/// endpoint facts. Persist it before transport; exact retries reuse its signed
/// ranges, endpoint authorization and recipient key without governance pins.
pub async fn author_and_create_ordinary_human_request(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    requester_did: &arkret_sdk::Did,
    device_id: &arkret_sdk::DeviceId,
    plan: OrdinaryHumanHistoryRequestPlan,
) -> anyhow::Result<(arkret_sdk::HistoryKeyRequestCreateOutcome, u64)> {
    let requester_principal_id = arkret_sdk::project_did_to_core_id(requester_did)?;
    if requester_principal_id != authority.principal_id {
        anyhow::bail!("history request actor differs from the explicit account authority");
    }
    let history = current_history_authority(
        state_store,
        api,
        authority,
        &plan.effective_scope,
        &arkret_sdk::ActorId::account(authority.clone()),
    )
    .await?;
    anyhow::ensure!(
        history.authorization_incarnation == plan.requester_authorization_incarnation,
        "history request membership changed before authoring"
    );
    let history_floor = history.history_floor_epoch.ok_or_else(|| {
        anyhow::anyhow!("frontier_unavailable: accepted MLS history floor is unavailable")
    })?;
    anyhow::ensure!(
        plan.requested_ranges
            .iter()
            .all(|range| range.from_epoch >= history_floor),
        "history request range is below the current scope floor"
    );
    let join_epoch = history.join_epoch.ok_or_else(|| {
        anyhow::anyhow!("frontier_unavailable: accepted MLS join epoch is unavailable")
    })?;
    if let Ok(durable) = runtime(state_store).durable_request(&plan.request_id) {
        if durable.request.effective_scope != plan.effective_scope
            || durable.request.requested_ranges != plan.requested_ranges
            || durable.request.expires_at != plan.expires_at
            || durable.request.requester_actor_id != arkret_sdk::ActorId::account(authority.clone())
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
        current_ordinary_human_endpoint_authorization(&http, authority, device_id).await?;
    let (_, public_key) =
        load_or_create_history_request_hpke_keypair_durable(secure_store, &plan.request_id).await?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("history request has no active endpoint signer"))?;
    if signer.device_id() != Some(device_id.as_str()) {
        anyhow::bail!("history request signer is not bound to the explicit current device");
    }
    let verification_method = signer.verification_method_for_principal(requester_did)?;
    let request = arkret_sdk::HistoryKeyRequest::build_signed_proof(
        verification_method.clone(),
        crate::clock::now_utc(),
        |requester_proof| arkret_sdk::HistoryKeyRequest {
            request_id: plan.request_id.clone(),
            kind: arkret_sdk::HistoryKeyRequestKind::Value,
            effective_scope: plan.effective_scope.clone(),
            requester_actor_id: arkret_sdk::ActorId::account(authority.clone()),
            requester_sender_domain: device_id.as_str().to_owned(),
            requester_author_profile: arkret_sdk::AuthorProfile::OrdinaryHuman,
            requester_endpoint_authorization: endpoint_authorization.clone(),
            requester_authorization_incarnation: plan.requester_authorization_incarnation.clone(),
            requested_ranges: plan.requested_ranges.clone(),
            recipient_hpke_public_key: URL_SAFE_NO_PAD.encode(&public_key),
            expires_at: plan.expires_at,
            requester_proof,
        },
        |bytes| {
            signer
                .detached_jws_over_payload(bytes)
                .map_err(|error| arkret_sdk::WireError::Protocol(error.to_string()))
        },
    )?;
    request.validate()?;
    let accepted =
        create_or_resume_authored_request(state_store, api, secure_store, request).await?;
    Ok((accepted, join_epoch))
}

async fn create_or_resume_authored_request(
    state_store: &StateStoreHandle,
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

fn scope_uses_exporter_history(
    state_store: &StateStoreHandle,
    scope: &arkret_sdk::HistoryEffectiveScope,
) -> bool {
    state_store.read(|store| match scope {
        arkret_sdk::HistoryEffectiveScope::Realm { realm_id } => store
            .realm_content_scheme(realm_id.as_str())
            .is_some_and(|scheme| scheme == "mls_exporter_aead_v1"),
        // A Circle MLS group freezes its own content scheme at its accepted
        // Genesis. `ak.component.circle.create.v1` is an ordered log, which
        // `sync/current-results.md` keeps out of the current cell set, so the
        // Station publishes no current value a client can read for it yet.
        // Fail closed rather than borrow the parent Realm's scheme.
        arkret_sdk::HistoryEffectiveScope::Circle { .. } => false,
    })
}

fn ranges_at_or_after(
    ranges: Vec<arkret_sdk::EpochRange>,
    floor: u64,
) -> Vec<arkret_sdk::EpochRange> {
    ranges
        .into_iter()
        .filter_map(|range| {
            (range.to_epoch >= floor).then_some(arkret_sdk::EpochRange {
                from_epoch: range.from_epoch.max(floor),
                to_epoch: range.to_epoch,
            })
        })
        .collect()
}

async fn current_member_signer_evidence_coordinates(
    api: &crate::transport::TransportClient,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<arkret_sdk::SignerEvidenceRef> {
    let http = http_client(api)?;
    let outcome = crate::transport::keys::query_keys(&http, authority, device_id.as_str()).await?;
    let record = outcome
        .devices_for(authority)
        .and_then(|devices| devices.get(device_id))
        .ok_or_else(|| anyhow::anyhow!("history source has no current attested device"))?;
    // The row was read at the exact `(authority, device_id)` selectors.
    let projection = crate::identity::device_directory::validate_self_device_row(record)?;
    if !record.is_usable_in_generation(outcome.generation_for(authority)) {
        anyhow::bail!("history source device generation is inactive");
    }
    let now = chrono::Utc::now();
    if !crate::identity::device_directory::projection_observation_is_fresh(projection, now)
        || !crate::identity::device_directory::projection_authorization_window_contains(
            projection, now,
        )
    {
        anyhow::bail!("history source device projection is not currently authorized");
    }
    // The reference is returned exactly as the Station projected it; it still
    // addresses the original complete immutable evidence object.
    Ok(record.signer_evidence_ref.clone())
}

fn build_signed_member_response(
    response_id: arkret_sdk::HistoryResponseId,
    request_record: &arkret_sdk::HistoryKeyRequestRecord,
    source_actor_id: &arkret_sdk::ActorId,
    source_sender_domain: &str,
    source_signer_evidence_ref: &arkret_sdk::SignerEvidenceRef,
    verification_method: &arkret_sdk::DidUrl,
    content: arkret_sdk::HistoryKeyResponseContent,
    signer: &crate::event_signer::InksonEventSigner,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<arkret_sdk::HistoryKeyResponseSendRequestBody> {
    let request_digest = request_record.request.request_digest()?;
    let request_receipt_digest = request_record.request_receipt.request_receipt_digest()?;
    Ok(
        arkret_sdk::HistoryKeyResponseSendRequestBody::build_signed_proof(
            verification_method.clone(),
            now,
            |source_proof| arkret_sdk::HistoryKeyResponseSendRequestBody {
                response_id: response_id.clone(),
                effective_scope: request_record.request.effective_scope.clone(),
                source_actor_id: source_actor_id.clone(),
                source_sender_domain: source_sender_domain.to_owned(),
                source_signer_evidence_ref: source_signer_evidence_ref.clone(),
                request_digest: request_digest.clone(),
                request_receipt_digest: request_receipt_digest.clone(),
                expires_at: request_record.request.expires_at,
                content: content.clone(),
                source_proof,
            },
            |bytes| {
                signer
                    .detached_jws_over_payload(bytes)
                    .map_err(|error| arkret_sdk::WireError::Protocol(error.to_string()))
            },
        )?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn build_member_source_attempt(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    source_did: &arkret_sdk::Did,
    // The source is this account: `authority` is its closed AccountId and
    // `source_actor_id` its principal, which must agree.
    authority: &arkret_sdk::AccountId,
    source_actor_id: &arkret_sdk::DidCoreId,
    source_device_id: &arkret_sdk::DeviceId,
    request_record: &arkret_sdk::HistoryKeyRequestRecord,
    local_secrets: &[arkret_sdk::LocalAuthoritativeHistorySecret],
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Option<garth::HistorySourceAttemptBundle>> {
    if request_record.request.expires_at <= now {
        return Ok(None);
    }
    if *source_actor_id != authority.principal_id {
        anyhow::bail!("history source actor does not belong to the active account");
    }
    let source_account_actor = arkret_sdk::ActorId::account(authority.clone());
    let mut selected =
        local_secrets
            .iter()
            .filter(|secret| {
                secret.effective_scope == request_record.request.effective_scope
                    && request_record.request.requested_ranges.iter().any(|range| {
                        range.from_epoch <= secret.epoch && secret.epoch <= range.to_epoch
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
    selected.sort_by_key(|secret| secret.epoch);
    selected.dedup_by_key(|secret| secret.epoch);
    if selected.is_empty() {
        return Ok(None);
    }

    let request_receipt_digest = request_record.request_receipt.request_receipt_digest()?;
    let history = current_history_authority(
        state_store,
        api,
        authority,
        &request_record.request.effective_scope,
        &request_record.request.requester_actor_id,
    )
    .await?;
    anyhow::ensure!(
        history.authorization_incarnation
            == request_record.request.requester_authorization_incarnation,
        "history target has left or rejoined since its request"
    );
    let history_floor = history.history_floor_epoch.ok_or_else(|| {
        anyhow::anyhow!("frontier_unavailable: accepted MLS history floor is unavailable")
    })?;
    selected.retain(|secret| secret.epoch >= history_floor);
    if selected.is_empty() {
        return Ok(None);
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("history source has no active endpoint signer"))?;
    if signer.device_id() != Some(source_device_id.as_str()) {
        anyhow::bail!("history source signer is not bound to the explicit current device");
    }
    let verification_method = signer.verification_method_for_principal(source_did)?;
    let source_signer_evidence_ref =
        current_member_signer_evidence_coordinates(api, authority, source_device_id).await?;
    // The source proof must be inside the newly attested device window.
    let now = arkret_sdk::canonical::normalize_timestamp_canonical(chrono::Utc::now());

    let manifest_response_id = arkret_sdk::HistoryResponseId::new(format!(
        "ak:history_response:{}",
        crate::operation::uuid_v7()
    ))?;
    let chunk_response_ids = (0..selected.len())
        .map(|_| {
            arkret_sdk::HistoryResponseId::new(format!(
                "ak:history_response:{}",
                crate::operation::uuid_v7()
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let descriptors = selected
        .iter()
        .zip(&chunk_response_ids)
        .enumerate()
        .map(
            |(chunk_index, (secret, response_id))| arkret_sdk::HistoryResponseChunkDescriptor {
                chunk_response_id: response_id.clone(),
                chunk_index: chunk_index as u64,
                covered_epoch_range: arkret_sdk::EpochRange {
                    from_epoch: secret.epoch,
                    to_epoch: secret.epoch,
                },
            },
        )
        .collect::<Vec<_>>();
    let manifest = build_signed_member_response(
        manifest_response_id,
        request_record,
        &source_account_actor,
        source_device_id.as_str(),
        &source_signer_evidence_ref,
        &verification_method,
        arkret_sdk::HistoryKeyResponseContent::Manifest(arkret_sdk::HistoryResponseManifest {
            kind: arkret_sdk::HistoryResponseManifestKind::Value,
            chunks: descriptors.clone(),
        }),
        signer.as_ref(),
        now,
    )?;
    let manifest_digest = manifest.manifest_digest()?;
    let authorized_ranges = canonical_ranges_for_epochs(selected.iter().map(|secret| secret.epoch));
    let admission = arkret_sdk::HistoryManifestAdmission {
        kind: arkret_sdk::HistoryManifestAdmissionKind::Value,
        manifest_digest: manifest_digest.clone(),
        request_digest: request_record.request.request_digest()?,
        request_receipt_digest,
        traversal_intent_digest: request_record
            .request_receipt
            .history_traversal_retention
            .traversal_intent_digest
            .clone(),
        authorized_ranges,
        t0_pass: arkret_sdk::HistoryManifestAdmissionPass::Value,
        manifest_admission_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    }
    .with_computed_digest()?;

    let mut chunks = Vec::with_capacity(selected.len());
    for ((secret, descriptor), response_id) in
        selected.iter().zip(&descriptors).zip(chunk_response_ids)
    {
        let seal_context = arkret_sdk::HistorySecretChunkSealContext {
            purpose: arkret_sdk::HistorySecretChunkSealPurpose::Value,
            manifest_admission_digest: admission.manifest_admission_digest.clone(),
            chunk_response_id: response_id.clone(),
            chunk_index: descriptor.chunk_index,
            source_actor_id: source_account_actor.clone(),
            source_sender_domain: source_device_id.as_str().to_owned(),
        };
        let plaintext = arkret_sdk::HistoryChunkPlaintext {
            kind: arkret_sdk::HistoryChunkPlaintextKind::Value,
            secret_range: arkret_sdk::HistorySecretRange {
                from_epoch: secret.epoch,
                to_epoch: secret.epoch,
                secrets_b64u: secret.secret_b64u.clone(),
            },
        };
        let sealed = arkret_crypto::secret_share::seal_history_secret_chunk(
            &request_record.request.recipient_hpke_public_key,
            &seal_context,
            &manifest_digest,
            &descriptor.covered_epoch_range,
            &plaintext,
        )?;
        let chunk = build_signed_member_response(
            response_id,
            request_record,
            &source_account_actor,
            source_device_id.as_str(),
            &source_signer_evidence_ref,
            &verification_method,
            arkret_sdk::HistoryKeyResponseContent::Chunk(sealed),
            signer.as_ref(),
            now,
        )?;
        chunks.push(garth::HistorySourceOutboundRecord::Direct {
            request: Box::new(chunk),
        });
    }
    Ok(Some(garth::HistorySourceAttemptBundle {
        request_id: request_record.request.request_id.clone(),
        manifest_admission_digest: admission.manifest_admission_digest,
        manifest: garth::HistorySourceOutboundRecord::Direct {
            request: Box::new(manifest),
        },
        chunks,
    }))
}

/// Publish a complete source attempt only after every canonical signed record
/// is durable in the secure content-addressed blob store. The Garth attempt
/// row is the atomic ready marker; callers may safely crash after this returns.
pub async fn stage_member_source_attempt(
    state_store: &StateStoreHandle,
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
    state_store: &StateStoreHandle,
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
                garth::HistorySourceAttemptStatus::PermanentlyRejected => {
                    outcome.permanently_rejected += 1
                }
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
    state_store: &StateStoreHandle,
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
/// join or same-Station route recovery is intentional: the service projection is the
/// authoritative discovery surface and request ids make repeated pages safe.
pub async fn discover_member_request_replicas(
    state_store: &StateStoreHandle,
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

/// Drive the ordinary-human private history-key protocol to convergence.
///
/// Request creation, source discovery/staging, durable replay and requester
/// response installation are deliberately one resumable workflow. Every
/// network object still passes the SDK and service T0/T1 checks; this driver
/// only supplies the liveness that the protocol surfaces cannot provide by
/// themselves.
#[allow(clippy::too_many_arguments)]
pub async fn converge_member_history_recovery(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    authority: &arkret_sdk::AccountId,
    requester_did: &arkret_sdk::Did,
    device_id: &arkret_sdk::DeviceId,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<HistoryRecoveryConvergenceOutcome> {
    let actor_id = arkret_sdk::project_did_to_core_id(requester_did)?;
    if actor_id != authority.principal_id {
        anyhow::bail!("history convergence actor differs from the explicit account authority");
    }
    let mut outcome = HistoryRecoveryConvergenceOutcome::default();

    let missing = crate::mls::runtime::missing_external_history_ranges(
        state_store,
        authority,
        requester_did.as_str(),
        device_id,
    )
    .map_err(anyhow::Error::msg)?;
    for (scope, requested_ranges) in missing {
        if requested_ranges.is_empty() || !scope_uses_exporter_history(state_store, &scope) {
            continue;
        }
        let history = match current_history_authority(
            state_store,
            api,
            authority,
            &scope,
            &arkret_sdk::ActorId::account(authority.clone()),
        )
        .await
        {
            Ok(history) => history,
            Err(error) => {
                outcome.pending_errors += 1;
                tracing::warn!(%error, "private history current authority remains pending");
                continue;
            }
        };
        let incarnation = history.authorization_incarnation;
        let Some(floor) = history.history_floor_epoch else {
            outcome.pending_errors += 1;
            continue;
        };
        let requested_ranges = ranges_at_or_after(requested_ranges, floor);
        if requested_ranges.is_empty() {
            continue;
        }
        let durable_requests = match runtime(state_store).durable_requests() {
            Ok(requests) => requests,
            Err(error) => {
                outcome.pending_errors += 1;
                tracing::warn!(%error, "private history requester intents remain pending");
                continue;
            }
        };
        let existing = durable_requests.into_iter().find(|durable| {
            durable.request.effective_scope == scope
                && durable.request.requester_actor_id
                    == arkret_sdk::ActorId::account(authority.clone())
                && durable.request.requester_authorization_incarnation == incarnation
                && durable
                    .request
                    .requested_ranges
                    .iter()
                    .all(|range| range.from_epoch >= floor)
                && ranges_cover(&durable.request.requested_ranges, &requested_ranges)
                && durable.request.expires_at > now + chrono::Duration::minutes(1)
        });
        let (request_id, requested_ranges, expires_at) = match existing {
            Some(durable) if durable.accepted.is_some() => continue,
            Some(durable) => (
                durable.request.request_id,
                durable.request.requested_ranges,
                durable.request.expires_at,
            ),
            None => (
                arkret_sdk::HistoryRequestId::new(format!(
                    "ak:history_request:{}",
                    crate::operation::uuid_v7()
                ))?,
                requested_ranges,
                arkret_sdk::canonical::normalize_timestamp_canonical(
                    now + chrono::Duration::hours(24),
                ),
            ),
        };
        let result = author_and_create_ordinary_human_request(
            state_store,
            api,
            secure_store.as_ref(),
            authority,
            requester_did,
            device_id,
            OrdinaryHumanHistoryRequestPlan {
                request_id,
                effective_scope: scope,
                requester_authorization_incarnation: incarnation,
                requested_ranges,
                expires_at,
            },
        )
        .await;
        match result {
            Ok(_) => outcome.requests_created_or_resumed += 1,
            Err(error) => {
                outcome.pending_errors += 1;
                tracing::warn!(%error, "private history request remains pending");
            }
        }
    }

    let local_sources = state_store
        .read(|store| {
            store.local_authoritative_history_secrets_for_backup(secure_store.as_ref(), authority)
        })
        .unwrap_or_else(|error| {
            outcome.pending_errors += 1;
            tracing::debug!(%error, "no local-authoritative history source material is available");
            Vec::new()
        });
    for (scope, secrets) in local_sources {
        if secrets.is_empty() || !scope_uses_exporter_history(state_store, &scope) {
            continue;
        }
        let (realm_id, circle_id) = match &scope {
            arkret_sdk::HistoryEffectiveScope::Realm { realm_id } => (realm_id.as_str(), None),
            arkret_sdk::HistoryEffectiveScope::Circle {
                realm_id,
                circle_id,
            } => (realm_id.as_str(), Some(circle_id.as_str())),
        };
        let mut cursor = None;
        loop {
            let page = match discover_member_request_replicas(
                state_store,
                api,
                realm_id,
                circle_id,
                cursor,
                Some(64),
            )
            .await
            {
                Ok(page) => page,
                Err(error) => {
                    outcome.pending_errors += 1;
                    tracing::warn!(%error, "private history request discovery remains pending");
                    break;
                }
            };
            for request_record in page.requests {
                if request_record.request.effective_scope != scope
                    || request_record.request.expires_at <= now
                {
                    continue;
                }
                let outbox = crate::state::history_source_outbox(state_store);
                let attempts = match outbox.attempts_for_request_source(
                    &request_record.request.request_id,
                    device_id.as_str(),
                ) {
                    Ok(attempts) => attempts,
                    Err(error) => {
                        outcome.pending_errors += 1;
                        tracing::warn!(request_id = %request_record.request.request_id, %error,
                            "private history source attempt lookup remains pending");
                        continue;
                    }
                };
                let uncovered_secrets = secrets
                    .iter()
                    .filter(|secret| !live_attempt_covers_epoch(&attempts, secret.epoch))
                    .cloned()
                    .collect::<Vec<_>>();
                let bundle = build_member_source_attempt(
                    state_store,
                    api,
                    requester_did,
                    authority,
                    &actor_id,
                    device_id,
                    &request_record,
                    &uncovered_secrets,
                    now,
                )
                .await;
                let bundle = match bundle {
                    Ok(Some(bundle)) => bundle,
                    Ok(None) => continue,
                    Err(error) => {
                        outcome.pending_errors += 1;
                        tracing::warn!(
                            request_id = %request_record.request.request_id,
                            %error,
                            "private history source attempt construction remains pending"
                        );
                        continue;
                    }
                };
                match stage_member_source_attempt(state_store, secure_store.as_ref(), bundle).await
                {
                    Ok(_) => outcome.source_attempts_staged += 1,
                    Err(error) => {
                        outcome.pending_errors += 1;
                        tracing::warn!(
                            request_id = %request_record.request.request_id,
                            %error,
                            "private history source attempt staging remains pending"
                        );
                    }
                }
            }
            if !page.limited {
                break;
            }
            cursor = page.cursor;
            if cursor.is_none() {
                outcome.pending_errors += 1;
                tracing::warn!(
                    "limited private history request page omitted its continuation cursor"
                );
                break;
            }
        }
    }

    match drain_source_outbox(state_store, api, secure_store.as_ref(), now).await {
        Ok(drained) => outcome.source_attempts_completed = drained.completed,
        Err(error) => {
            outcome.pending_errors += 1;
            tracing::warn!(%error, "private history source outbox remains pending");
        }
    }
    for request_id in accepted_history_request_ids(state_store)? {
        let installed = verify_and_install_response_page_from_local_state(
            state_store,
            api,
            secure_store.clone(),
            authority,
            device_id,
            &request_id,
            Some(64),
            now,
        )
        .await;
        match installed {
            Ok(installed) => outcome.response_records_installed += installed.installed,
            Err(error) => {
                outcome.pending_errors += 1;
                tracing::warn!(%request_id, %error, "private history response stream remains pending");
            }
        }
    }
    Ok(outcome)
}

fn ensure_history_receiver_station(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    request_id: &arkret_sdk::HistoryRequestId,
) -> anyhow::Result<()> {
    let authority = state_store
        .read(|store| store.active_authority())
        .ok_or_else(|| anyhow::anyhow!("history receiver has no active account"))?;
    let durable = runtime(state_store).durable_request(request_id)?;
    let accepted = durable
        .accepted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("history request is not accepted"))?;
    anyhow::ensure!(
        durable.request.requester_actor_id == arkret_sdk::ActorId::account(authority.clone())
            && accepted.request_receipt.release_id == authority.station_id,
        "history response capability belongs to another account or Station"
    );
    let profiles = crate::config::LocalConfigStore::default().load_profiles();
    let profile = profiles
        .active()
        .ok_or_else(|| anyhow::anyhow!("history receiver has no active Station route"))?;
    anyhow::ensure!(
        profile.account.authority == authority
            && crate::config::same_server_url(
                profile.account.server_url.as_str(),
                api.base_url().as_str()
            ),
        "history response endpoint differs from the account's configured Station"
    );
    Ok(())
}

pub async fn acquire_response_page(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
) -> anyhow::Result<arkret_sdk::HistoryKeyResponseListOutcome> {
    ensure_history_receiver_station(state_store, api, request_id)?;
    let http = http_client(api)?;
    runtime(state_store)
        .acquire_response_page(&http, secure_store, request_id, limit)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Install a page from the account's Station, checking only cryptographic payloads
/// and the receiver's actual MLS state.
pub async fn verify_and_install_response_page<VerifyExternalSourceKey>(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
    now: chrono::DateTime<chrono::Utc>,
    verify_external_source_key: VerifyExternalSourceKey,
) -> anyhow::Result<HistoryResponsePageInstallOutcome>
where
    VerifyExternalSourceKey: for<'a> Fn(
            &'a arkret_sdk::HistoryKeyResponseSendRequestBody,
            &'a arkret_sdk::MinimalMetadataMlsLeafSignerEvidence,
        ) -> arkret_sdk::HistorySourceProofVerificationFuture<'a>
        + Clone,
{
    let session_epoch = crate::identity::device_directory::cache_epoch();
    let page = acquire_response_page(state_store, api, secure_store, request_id, limit).await?;
    if page.entries.is_empty() {
        return Ok(HistoryResponsePageInstallOutcome::default());
    }
    page.validate()?;
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
    let mut outcome = HistoryResponsePageInstallOutcome::default();

    for entry in &page.entries {
        anyhow::ensure!(
            crate::identity::device_directory::cache_epoch() == session_epoch,
            "history receiver session changed"
        );
        ensure_history_receiver_station(state_store, api, request_id)?;
        let arkret_sdk::HistoryResponsePageEntry::Record { record } = entry else {
            let arkret_sdk::HistoryResponsePageEntry::Lost { lost_record } = entry else {
                unreachable!("history response stream page entry is a closed union")
            };
            lost_record.validate()?;
            anyhow::ensure!(
                lost_record.lost_at <= accepted.request.expires_at,
                "history lost record exceeds request lifetime"
            );
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
        let signer_result = page
            .source_signer_results
            .iter()
            .find(|result| {
                result.evidence_ref() == &record.source_record.source_signer_evidence_ref
            })
            .ok_or_else(|| anyhow::anyhow!("history page omits source signer result"))?;
        let manifest = match &record.source_record.content {
            arkret_sdk::HistoryKeyResponseContent::Chunk(chunk) => runtime
                .verified_manifest(request_id, &chunk.manifest_digest)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .map(|manifest| -> anyhow::Result<_> {
                    Ok(arkret_sdk::VerifiedHistoryManifest {
                        response_id: manifest.response_id,
                        source_actor_id: manifest.source_actor_id,
                        source_sender_domain: manifest.source_sender_domain,
                        manifest_digest: manifest.manifest_digest,
                        manifest_admission_digest: manifest.manifest_admission_digest,
                        chunks: manifest.chunks,
                    })
                })
                .transpose()?,
            arkret_sdk::HistoryKeyResponseContent::Manifest(_) => None,
        };
        let verified = match arkret_sdk::verify_history_response_record(
            &accepted,
            record,
            signer_result,
            manifest.as_ref(),
            now,
            verify_external_source_key.clone(),
        )
        .await
        {
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
                let prepared = async {
                    let plaintext = arkret_crypto::secret_share::open_history_secret_chunk(
                        &private_key_b64u,
                        &chunk.seal_context,
                        &chunk.covered_epoch_range,
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
                    let cipher_suite = page
                        .cipher_suite
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("history page omits pinned MLS suite"))?;
                    let kdf_nh =
                        usize::from(arkret_sdk::registered_mls_ciphersuite_kdf_nh(cipher_suite)?);
                    let count = chunk
                        .covered_epoch_range
                        .to_epoch
                        .checked_sub(chunk.covered_epoch_range.from_epoch)
                        .and_then(|value| value.checked_add(1))
                        .and_then(|value| usize::try_from(value).ok())
                        .ok_or_else(|| anyhow::anyhow!("history epoch range overflow"))?;
                    let expected_len = count
                        .checked_mul(kdf_nh)
                        .ok_or_else(|| anyhow::anyhow!("history secret range length overflow"))?;
                    let secret_bytes = arkret_sdk::base64url_decode(
                        plaintext.secret_range.secrets_b64u.as_bytes(),
                    )?;
                    if secret_bytes.len() != expected_len {
                        return Err(anyhow::anyhow!(
                            "history secret range byte length does not equal winning MLS KDF.Nh sum"
                        ));
                    }
                    let source_record_digest = record.source_record.source_record_digest()?;
                    let mut offset = 0_usize;
                    let mut candidates = Vec::with_capacity(count);
                    for epoch in
                        chunk.covered_epoch_range.from_epoch..=chunk.covered_epoch_range.to_epoch
                    {
                        let next = offset + kdf_nh;
                        let secret = secret_bytes[offset..next].to_vec();
                        let material_key = arkret_sdk::HistoryCandidateMaterialKey {
                            effective_scope: accepted.request.effective_scope.clone(),
                            mls_group_id: accepted
                                .request
                                .effective_scope
                                .canonical_mls_group_id()?,
                            epoch,
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
                        candidates.push((material_key, secret, attribution, cipher_suite.clone()));
                        offset = next;
                    }
                    Ok::<_, anyhow::Error>(candidates)
                }
                .await;
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
                let group_id = accepted.request.effective_scope.canonical_mls_group_id()?;
                for (material_key, secret, attribution, cipher_suite) in candidates {
                    let secret_bytes = secret.as_slice();
                    state_store
                        .stage_then_commit(
                            |store| {
                                store
                                    .record_history_epoch_cipher_suite(
                                        &history_scope,
                                        &group_id,
                                        material_key.epoch,
                                        &cipher_suite,
                                    )
                                    .map_err(anyhow::Error::msg)?;
                                store.stage_history_candidate(
                                    secure_store,
                                    secret_bytes,
                                    attribution,
                                    now,
                                )
                            },
                            move |staged| async move {
                                garth::persist_staged_history_candidate_secret(
                                    secure_store,
                                    &staged,
                                    secret_bytes,
                                )
                                .await
                                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                                Ok(staged)
                            },
                            |store, staged| store.commit_history_candidate(secure_store, staged),
                        )
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
    anyhow::ensure!(
        crate::identity::device_directory::cache_epoch() == session_epoch,
        "history receiver session changed before ACK"
    );
    acknowledge_ready_page(state_store, api, secure_store, request_id).await?;
    Ok(outcome)
}

async fn verify_history_external_source_key(
    state_store: StateStoreHandle,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    source_record: &arkret_sdk::HistoryKeyResponseSendRequestBody,
    signer_evidence: &arkret_sdk::MinimalMetadataMlsLeafSignerEvidence,
    accepted_transition: &arkret_sdk::MlsEpochHead,
) -> Result<arkret_sdk::signatures::proof::PublicKeyMaterial, arkret_sdk::WireError> {
    let realm_id = match &signer_evidence.effective_scope {
        arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
        | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    };
    let local = state_store
        .read(|store| {
            store.locally_authenticated_identity_link(
                realm_id,
                &signer_evidence.mls_group_id,
                signer_evidence.epoch,
                signer_evidence.leaf_index,
            )
        })
        .ok_or_else(|| {
            arkret_sdk::WireError::Protocol(
                "minimal-metadata history source has no locally received IdentityLink".to_owned(),
            )
        })?;
    let identity_link_bytes =
        arkret_sdk::base64url_decode(local.identity_link_canonical_bytes_b64u.as_str().as_bytes())?;
    let leaf_node_bytes =
        arkret_sdk::base64url_decode(local.leaf_node_canonical_bytes_b64u.as_str().as_bytes())?;
    if local.identity_link_digest
        != arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&identity_link_bytes))?
        || local.leaf_node_digest
            != arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&leaf_node_bytes))?
        || local.leaf_node_digest != signer_evidence.leaf_node_digest
        || local.winning_group_state_ref != signer_evidence.winning_group_state_transition_ref
    {
        return Err(arkret_sdk::WireError::Protocol(
            "minimal-metadata local IdentityLink cache is corrupt or mismatched".to_owned(),
        ));
    }
    let effective_scope = match &signer_evidence.effective_scope {
        arkret_sdk::HistoryEffectiveScope::Realm { realm_id } => arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_sdk::HistoryEffectiveScope::Circle {
            realm_id,
            circle_id,
        } => arkret_sdk::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
    };
    let winning_group_state = state_store
        .read(|store| {
            crate::mls::runtime::minimal_metadata_author_view_for_scope(
                store,
                secure_store.as_ref(),
                &authority,
                &device_id,
                &effective_scope,
                &signer_evidence.mls_group_id,
                signer_evidence.epoch,
                signer_evidence.winning_group_state_transition_ref.as_str(),
            )
        })
        .ok_or_else(|| {
            arkret_sdk::WireError::Protocol(
                "minimal-metadata history source has no local winning MLS state".to_owned(),
            )
        })?;
    arkret_sdk::verify_minimal_metadata_history_source_local_state(
        source_record,
        signer_evidence,
        accepted_transition,
        &local.identity_link,
        &identity_link_bytes,
        &winning_group_state,
    )
}

/// Production response stream installer with the only supported external trust
/// boundary wired to Inkson's durable MLS state.
#[allow(clippy::too_many_arguments)]
pub async fn verify_and_install_response_page_from_local_state(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: std::sync::Arc<dyn SecureKeyStore + Send + Sync>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    request_id: &arkret_sdk::HistoryRequestId,
    limit: Option<u8>,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<HistoryResponsePageInstallOutcome> {
    let session_epoch = crate::identity::device_directory::cache_epoch();
    let durable = runtime(state_store).durable_request(request_id)?;
    anyhow::ensure!(
        state_store.read(|store| store.active_authority()).as_ref() == Some(authority),
        "history receiver account changed"
    );
    anyhow::ensure!(
        durable.request.requester_actor_id == arkret_sdk::ActorId::account(authority.clone()),
        "history receiver differs from durable request account"
    );
    let accepted = durable
        .accepted
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("history request is not accepted"))?;
    anyhow::ensure!(
        accepted.request_receipt.release_id == authority.station_id,
        "history response release is not the account Station"
    );
    let page =
        acquire_response_page(state_store, api, secure_store.as_ref(), request_id, limit).await?;
    page.validate()?;
    let http = http_client(api)?;
    let mut transitions = std::collections::BTreeMap::new();
    for result in &page.source_signer_results {
        let arkret_sdk::HistorySourceSignerOutcome::ReceiverMls {
            signer_evidence, ..
        } = result
        else {
            continue;
        };
        let query = arkret_sdk::MlsAcceptedArtifactRequestBody {
            effective_scope: signer_evidence.effective_scope.clone().into(),
            mls_group_id: arkret_sdk::Base64UrlString::new(signer_evidence.mls_group_id.clone())
                .map_err(anyhow::Error::msg)?,
            artifact_ref: signer_evidence.winning_group_state_transition_ref.clone(),
        };
        let realm_id = match &signer_evidence.effective_scope {
            arkret_sdk::HistoryEffectiveScope::Realm { realm_id }
            | arkret_sdk::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
        };
        anyhow::ensure!(
            state_store
                .read(|store| store.locally_authenticated_identity_link(
                    realm_id,
                    &signer_evidence.mls_group_id,
                    signer_evidence.epoch,
                    signer_evidence.leaf_index,
                ))
                .is_some(),
            "minimal-metadata history is waiting for its local IdentityLink"
        );
        anyhow::ensure!(
            state_store
                .read(
                    |store| crate::mls::runtime::minimal_metadata_author_view_for_scope(
                        store,
                        secure_store.as_ref(),
                        authority,
                        device_id,
                        &query.effective_scope,
                        &signer_evidence.mls_group_id,
                        signer_evidence.epoch,
                        signer_evidence.winning_group_state_transition_ref.as_str(),
                    )
                )
                .is_some(),
            "minimal-metadata history is waiting for its local MLS state"
        );
        let outcome = http.mls_accepted_artifact(&query).await?;
        outcome.validate_for_request(&query)?;
        transitions.insert(
            result.evidence_ref().as_ref().to_owned(),
            outcome
                .transition_head
                .epoch_head(&outcome.governance_binding)?,
        );
    }
    anyhow::ensure!(
        crate::identity::device_directory::cache_epoch() == session_epoch
            && state_store.read(|store| store.active_authority()).as_ref() == Some(authority),
        "account session changed during history acquisition"
    );
    let transitions = std::sync::Arc::new(transitions);
    let verifier_store = secure_store.clone();
    let verifier_authority = authority.clone();
    let verifier_device_id = device_id.clone();
    let verifier_state_store = state_store.clone();
    verify_and_install_response_page(
        state_store,
        api,
        secure_store.as_ref(),
        request_id,
        limit,
        now,
        move |source_record, signer_evidence| {
            let transitions = transitions.clone();
            let state = verifier_state_store.clone();
            let secure = verifier_store.clone();
            let authority = verifier_authority.clone();
            let device = verifier_device_id.clone();
            Box::pin(async move {
                let head = transitions
                    .get(source_record.source_signer_evidence_ref.as_ref())
                    .ok_or_else(|| {
                        arkret_sdk::WireError::Protocol(
                            "history MLS transition is unavailable".to_owned(),
                        )
                    })?;
                verify_history_external_source_key(
                    state,
                    secure,
                    authority,
                    device,
                    source_record,
                    signer_evidence,
                    head,
                )
                .await
            })
        },
    )
    .await
}

pub async fn record_response_disposition(
    state_store: &StateStoreHandle,
    request_id: &arkret_sdk::HistoryRequestId,
    disposition: arkret_sdk::HistoryResponseAckEntry,
) -> anyhow::Result<()> {
    runtime(state_store)
        .record_response_disposition(request_id, disposition)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub async fn acknowledge_ready_page(
    state_store: &StateStoreHandle,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    request_id: &arkret_sdk::HistoryRequestId,
) -> anyhow::Result<arkret_sdk::HistoryKeyResponseAckOutcome> {
    ensure_history_receiver_station(state_store, api, request_id)?;
    let http = http_client(api)?;
    runtime(state_store)
        .acknowledge_ready_page(&http, secure_store, request_id)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_ranges_exclude_prejoin_without_losing_authorized_epochs() {
        let ranges = vec![
            arkret_sdk::EpochRange {
                from_epoch: 0,
                to_epoch: 2,
            },
            arkret_sdk::EpochRange {
                from_epoch: 5,
                to_epoch: 8,
            },
        ];
        assert_eq!(ranges_at_or_after(ranges.clone(), 0), ranges);
        assert_eq!(
            ranges_at_or_after(ranges.clone(), 1),
            vec![
                arkret_sdk::EpochRange {
                    from_epoch: 1,
                    to_epoch: 2
                },
                arkret_sdk::EpochRange {
                    from_epoch: 5,
                    to_epoch: 8
                },
            ]
        );
        assert_eq!(
            ranges_at_or_after(ranges.clone(), 6),
            vec![arkret_sdk::EpochRange {
                from_epoch: 6,
                to_epoch: 8
            },]
        );
        assert!(ranges_at_or_after(ranges, u64::MAX).is_empty());
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
        // Browser secure storage wraps UTF-8 values. Random scalar bytes must
        // never be passed directly: native memory storage alone hid that bug.
        let stored = store
            .get_secret_bytes(&history_request_hpke_private_key(&first))
            .unwrap()
            .unwrap();
        let encoded = std::str::from_utf8(stored.as_ref()).unwrap();
        assert_eq!(encoded, arkret_sdk::base64url_encode(&first_pair.0));
        assert_eq!(
            load_history_request_hpke_private_key(&store, &first)
                .unwrap()
                .unwrap(),
            first_pair.0
        );
    }

    #[tokio::test]
    async fn history_request_hpke_storage_rejects_unencoded_private_bytes() {
        let store = crate::secure_key_store::MemorySecureKeyStore::new();
        let request = arkret_sdk::HistoryRequestId::new(
            "ak:history_request:01964137-0000-7000-8000-000000000003".to_owned(),
        )
        .unwrap();
        store
            .put_secret(
                &history_request_hpke_private_key(&request),
                &[255; 32],
                garth::PutSecretOptions {
                    durability: garth::SecretDurability::DurableBeforeReturn,
                    class: garth::SecretClass::MlsSecret,
                },
            )
            .await
            .unwrap();
        assert!(load_history_request_hpke_private_key(&store, &request).is_err());
    }
}
