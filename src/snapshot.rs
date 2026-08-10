use chrono::{DateTime, Duration, Utc};

use crate::state::LocalStateStore;
use crate::transport::TransportClient;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFallbackReason {
    pub code: String,
    pub message: String,
}

impl SnapshotFallbackReason {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(arkret_sdk::ErrorCode::SNAPSHOT_UNAVAILABLE, message)
    }

    pub fn from_validation(error: arkret_sdk::SnapshotValidationError) -> Self {
        Self::new(error.code.as_str(), error.message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotTrustState {
    LowerTrust,
    Verified,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBootstrapResult {
    pub manifest_id: String,
    pub item_count: usize,
    pub chunk_count: usize,
    pub source_event_ids: Vec<String>,
    pub trust_state: SnapshotTrustState,
}

pub async fn download_verify_and_apply_snapshot<R>(
    api: &TransportClient,
    store: &mut LocalStateStore,
    realm_id: &str,
    service_id: &arkret_sdk::Did,
    resolver: &R,
    now: DateTime<Utc>,
) -> Result<SnapshotBootstrapResult, SnapshotFallbackReason>
where
    R: arkret_sdk::DidResolver + ?Sized,
{
    let snapshot_clients =
        crate::transport::EndpointClients::from_http(api.sdk_http_client().map_err(|error| {
            SnapshotFallbackReason::unavailable(format!("snapshot transport failed: {error}"))
        })?);
    let manifest = match snapshot_clients.directory().snapshot_head(realm_id).await {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return Err(SnapshotFallbackReason::unavailable(
                "snapshot head unavailable; falling back to event replay",
            ));
        }
        Err(error) => {
            return Err(SnapshotFallbackReason::unavailable(format!(
                "snapshot head failed: {error}"
            )));
        }
    };

    let mut chunks = Vec::with_capacity(manifest.chunks.len());
    for descriptor in &manifest.chunks {
        let chunk = snapshot_clients
            .blob()
            .download_snapshot_chunk_verified(descriptor)
            .await
            .map_err(|error| {
                SnapshotFallbackReason::new(
                    arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str(),
                    format!("snapshot chunk download failed: {error}"),
                )
            })?;
        chunks.push(chunk);
    }

    let result = verify_snapshot_package(&manifest, &chunks, service_id, resolver, now)?;
    store
        .apply_snapshot_chunks(&manifest, &chunks, result.trust_state.clone())
        .map_err(|error| {
            SnapshotFallbackReason::new(
                arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str(),
                format!("snapshot import failed: {error}"),
            )
        })?;
    Ok(result)
}

pub fn verify_snapshot_package<R>(
    manifest: &arkret_sdk::SnapshotManifest,
    chunks: &[arkret_sdk::SnapshotChunkPayload],
    service_id: &arkret_sdk::Did,
    resolver: &R,
    now: DateTime<Utc>,
) -> Result<SnapshotBootstrapResult, SnapshotFallbackReason>
where
    R: arkret_sdk::DidResolver + ?Sized,
{
    verify_snapshot_signature_and_authority(manifest, service_id, resolver, now)?;
    let report = arkret_sdk::verify_snapshot_manifest(
        manifest,
        chunks,
        &arkret_sdk::SnapshotVerifyOptions::standard(now, arkret_sdk::SNAPSHOT_REDUCER_PROFILE_V1),
    )
    .map_err(SnapshotFallbackReason::from_validation)?;
    let trust_state = match manifest.security_class {
        arkret_sdk::SnapshotSecurityClass::Standard => SnapshotTrustState::LowerTrust,
        arkret_sdk::SnapshotSecurityClass::HighAssurance => SnapshotTrustState::Verified,
    };
    Ok(SnapshotBootstrapResult {
        manifest_id: manifest.id.to_string(),
        item_count: report.item_count,
        chunk_count: report.chunk_count,
        source_event_ids: report
            .source_event_ids
            .into_iter()
            .map(|event_id| event_id.to_string())
            .collect(),
        trust_state,
    })
}

pub fn verify_snapshot_signature_and_authority<R>(
    manifest: &arkret_sdk::SnapshotManifest,
    service_id: &arkret_sdk::Did,
    resolver: &R,
    now: DateTime<Utc>,
) -> Result<(), SnapshotFallbackReason>
where
    R: arkret_sdk::DidResolver + ?Sized,
{
    if &manifest.created_by != service_id {
        return Err(SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::SnapshotAuthorityUnverified.as_str(),
            "snapshot created_by does not match the principal server service_id",
        ));
    }
    if manifest.authority_binding.issuer != manifest.created_by {
        return Err(SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::SnapshotAuthorityUnverified.as_str(),
            "snapshot authority_binding.issuer does not match created_by",
        ));
    }

    let canonical_bytes = manifest.signature_payload_bytes().map_err(|error| {
        SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str(),
            format!("snapshot manifest canonicalization failed: {error}"),
        )
    })?;
    let expected_digest = manifest.expected_signature_digest().map_err(|error| {
        SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str(),
            format!("snapshot signature digest failed: {error}"),
        )
    })?;
    let proof = manifest.signature_as_proof();
    let created_by_actor = arkret_sdk::ActorId::from(
        arkret_sdk::project_full_id_to_core_id(&manifest.created_by).map_err(|error| {
            SnapshotFallbackReason::new(
                arkret_sdk::SnapshotValidationCode::SnapshotAuthorityUnverified.as_str(),
                format!("snapshot created_by full_id is invalid: {error}"),
            )
        })?,
    );
    let mut context = arkret_sdk::signatures::ProofVerificationContext::new(
        created_by_actor.clone(),
        expected_digest,
    );
    context.now = now;
    context.replay_window = snapshot_replay_window(manifest.security_class.clone());
    let verification = arkret_sdk::verify_canonical_proof_with_did_resolver(
        &canonical_bytes,
        &proof,
        &created_by_actor,
        &context,
        resolver,
    )
    .map_err(|error| {
        SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::SnapshotAuthorityUnverified.as_str(),
            format!("snapshot signature verification failed: {error}"),
        )
    })?;
    if !verification.valid {
        return Err(SnapshotFallbackReason::new(
            arkret_sdk::SnapshotValidationCode::SnapshotAuthorityUnverified.as_str(),
            "snapshot signature verification returned valid=false",
        ));
    }
    Ok(())
}

fn snapshot_replay_window(security_class: arkret_sdk::SnapshotSecurityClass) -> Duration {
    match security_class {
        arkret_sdk::SnapshotSecurityClass::Standard => {
            Duration::milliseconds(arkret_sdk::SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS)
        }
        arkret_sdk::SnapshotSecurityClass::HighAssurance => {
            Duration::milliseconds(arkret_sdk::SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_reason_preserves_registry_code() {
        let reason =
            SnapshotFallbackReason::from_validation(arkret_sdk::SnapshotValidationError::new(
                arkret_sdk::SnapshotValidationCode::DigestMismatch,
                "chunk digest mismatch",
            ));
        assert_eq!(reason.code, arkret_sdk::ErrorCode::DIGEST_MISMATCH);
        assert!(reason.message.contains("digest"));
    }

    #[test]
    fn standard_snapshot_is_lower_trust_until_replayed() {
        assert_eq!(
            snapshot_replay_window(arkret_sdk::SnapshotSecurityClass::Standard),
            Duration::milliseconds(arkret_sdk::SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS)
        );
    }
}
