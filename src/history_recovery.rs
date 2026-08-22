use std::future::Future;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryResponsePageInstallOutcome {
    pub installed: usize,
    pub cryptographically_rejected: usize,
}

struct ResponseCapabilityOpener<'a> {
    secure_store: &'a dyn SecureKeyStore,
    authority: &'a arkret_sdk::PrincipalAuthorityKey,
    device_id: &'a arkret_sdk::DeviceId,
}

impl garth::HistoryResponseCapabilityOpener for ResponseCapabilityOpener<'_> {
    fn open_response_capability<'a>(
        &'a self,
        outcome: &'a arkret_sdk::HistoryKeyRequestCreateOutcome,
    ) -> impl Future<Output = garth::Result<String>> + garth::MaybeSend + 'a {
        async move {
            let private_key = crate::mls::runtime::load_device_hpke_private_key(
                self.secure_store,
                self.authority,
                self.device_id,
            )
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
}

struct ReceiptTraversal<'a> {
    api: &'a crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
}

impl garth::ReceiptBoundHistoryTraversal for ReceiptTraversal<'_> {
    fn acquire_and_verify<'a>(
        &'a self,
        retention: &'a arkret_sdk::HistoryGovernanceTraversalRetention,
        access: &'a arkret_sdk::SelfHistoryTraversalAccess,
    ) -> impl Future<Output = garth::Result<garth::VerifiedHistoryTraversal>> + garth::MaybeSend + 'a
    {
        async move {
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

/// Pack one exporter scope's device-local authoritative records into the SDK's
/// closed portable `mls_history` keybag. Candidate-ledger material is not an
/// input to this function and cannot cross the backup boundary.
pub fn pack_local_history_backup(
    state_store: &LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    mls_group_id: &str,
    kdf_nh: usize,
) -> anyhow::Result<arkret_models_crypto::KeyBackupKeybag> {
    let history_scope = arkret_sdk::HistoryEffectiveScope::try_from(effective_scope.clone())?;
    let records =
        state_store.local_authoritative_history_records_for(effective_scope, mls_group_id);
    arkret_state::history_backup::pack_local_authoritative_history_backup(
        &history_scope,
        &records,
        kdf_nh,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Install a decrypted portable `mls_history` keybag as bounded external
/// candidates. Restore never writes the local-authoritative ledger and never
/// reconstructs active MLS state, leaf identity, ratchet or counters.
pub async fn install_portable_history_backup(
    state_store: &mut LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    plaintext: &arkret_models_crypto::KeyBackupPlaintext,
    producer_actor_id: &arkret_sdk::DidCoreId,
    mls_ciphersuite: &str,
    kdf_nh: usize,
    first_observed_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<usize> {
    let restored = arkret_state::history_backup::restore_history_backup_candidates(
        plaintext,
        producer_actor_id,
        kdf_nh,
        first_observed_at,
    )?;
    let (effective_scope, mls_group_id) = match &plaintext.keybag {
        arkret_models_crypto::KeyBackupKeybag::MlsHistory {
            effective_scope, ..
        } => (
            arkret_sdk::ScopeRef::from(effective_scope.clone()),
            effective_scope.canonical_mls_group_id()?,
        ),
        _ => anyhow::bail!("portable history restore requires an mls_history keybag"),
    };
    let mut installed = 0;
    for candidate in restored {
        let epoch = candidate.attribution.material_key().epoch;
        state_store
            .record_history_epoch_cipher_suite(
                &effective_scope,
                &mls_group_id,
                epoch,
                mls_ciphersuite,
            )
            .map_err(anyhow::Error::msg)?;
        if state_store
            .receive_history_candidate(
                secure_store,
                &candidate.secret,
                candidate.attribution,
                first_observed_at,
            )
            .await?
        {
            installed += 1;
        }
    }
    Ok(installed)
}

fn http_client(api: &crate::transport::TransportClient) -> anyhow::Result<arkret_sdk::Client> {
    api.sdk_http_client()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub async fn create_or_resume_request(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
    request: arkret_sdk::HistoryKeyRequest,
) -> anyhow::Result<arkret_sdk::HistoryKeyRequestCreateOutcome> {
    let http = http_client(api)?;
    runtime(state_store)
        .create_or_resume_request(
            &http,
            &ResponseCapabilityOpener {
                secure_store,
                authority,
                device_id,
            },
            secure_store,
            request,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
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
#[allow(clippy::too_many_arguments)]
pub async fn verify_and_install_response_page<VerifyExternalSourceKey>(
    mut state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
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
    let private_key =
        crate::mls::runtime::load_device_hpke_private_key(secure_store, authority, device_id)?
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
                                expires_at: now + chrono::Duration::days(30),
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
        authority,
        device_id,
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

/// Stage a complete manifest plus every named chunk. All canonical bytes land
/// in the hardened content-addressed store before the durable attempt marker
/// is published.
pub async fn stage_response_attempt(
    state_store: SyncSignal<LocalStateStore>,
    bundle: garth::HistorySourceAttemptBundle,
) -> anyhow::Result<garth::HistorySourceAttemptIdentity> {
    crate::state::history_source_outbox(state_store)
        .stage_attempt(&crate::state::InksonHistorySourceBlobStore, bundle)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Replay one ready attempt from its exact staged bytes. Direct and relayed
/// records are closed variants inside the bundle; callers cannot bypass the
/// complete-attempt marker with a singular send.
pub async fn replay_response_attempt(
    state_store: SyncSignal<LocalStateStore>,
    api: &crate::transport::TransportClient,
    identity: &garth::HistorySourceAttemptIdentity,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<garth::DurableHistorySourceAttempt> {
    let http = http_client(api)?;
    crate::state::history_source_outbox(state_store)
        .replay_attempt(
            &http,
            &crate::state::InksonHistorySourceBlobStore,
            identity,
            now,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Remove blobs left by a crash before their ready marker committed.
pub fn reconcile_history_source_outbox(
    state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<usize> {
    crate::state::history_source_outbox(state_store)
        .reconcile_orphan_blobs(&crate::state::InksonHistorySourceBlobStore)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
