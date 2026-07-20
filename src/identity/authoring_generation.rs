//! Durable outbound authoring-generation fence.
//!
//! A queued Event is bound to the verified device authority generation that
//! authored it. Before every replay the current keys projection is fetched
//! again and compared exactly. Recovery therefore cannot accidentally revive
//! queued work signed by an old B-model DID generation, an old A-model SSK
//! generation, or a controller generation that no longer authorizes a managed
//! Agent write.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use garth::{OutboundGenerationFence, OutboundGenerationFenceDecision};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthoringAuthorityModel {
    CrossSigning,
    EnrollmentAuthority,
    ManagedAgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoringGeneration {
    pub(crate) authority_model: AuthoringAuthorityModel,
    pub(crate) authority_principal_id: String,
    pub(crate) generation_ref: String,
}

impl AuthoringGeneration {
    fn managed_agent(
        controller: &str,
        controller_generation: &Self,
        authorization_ref: &str,
    ) -> arkret_sdk::Result<Self> {
        let authorization_ref = authorization_ref.trim();
        if authorization_ref.is_empty() {
            return Err(arkret_sdk::Error::Protocol(
                "managed Agent authoring requires authorization_ref".to_owned(),
            ));
        }
        let generation_ref = arkret_sdk::canonical::canonical_sha256(&serde_json::json!({
            "controller_authority_model": controller_generation.authority_model,
            "controller_generation_ref": controller_generation.generation_ref,
            "authorization_ref": authorization_ref,
        }))?;
        Ok(Self {
            authority_model: AuthoringAuthorityModel::ManagedAgent,
            authority_principal_id: controller.to_owned(),
            generation_ref,
        })
    }
}

fn verified_generation_cache() -> &'static Mutex<BTreeMap<String, AuthoringGeneration>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, AuthoringGeneration>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn principal_generation_cache_key(principal_id: &str, device_id: &str) -> String {
    format!("{principal_id}\u{1f}{device_id}")
}

fn cache_verified_principal_generation(
    principal_id: &str,
    device_id: &str,
    generation: &AuthoringGeneration,
) {
    verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            principal_generation_cache_key(principal_id, device_id),
            generation.clone(),
        );
}

pub(crate) fn reset_verified_authoring_generations() {
    verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

pub(crate) fn cached_event_authoring_generation(
    event: &arkret_sdk::Event,
) -> anyhow::Result<Option<AuthoringGeneration>> {
    let authority_principal = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .as_str();
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured for generation-fenced write")
    })?;
    let device_id = signer.device_id().ok_or_else(|| {
        anyhow::anyhow!("active signer has no device_id for generation-fenced write")
    })?;
    let Some(controller_generation) = verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&principal_generation_cache_key(
            authority_principal,
            device_id,
        ))
        .cloned()
    else {
        return Ok(None);
    };

    if event.executed_by.is_some() && authority_principal != event.actor_id.as_str() {
        return AuthoringGeneration::managed_agent(
            authority_principal,
            &controller_generation,
            event.authorization_ref.as_deref().unwrap_or_default(),
        )
        .map(Some)
        .map_err(anyhow::Error::from);
    }
    Ok(Some(controller_generation))
}

pub(crate) async fn resolve_event_authoring_generation(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<AuthoringGeneration> {
    match resolve_current_event_authoring_generation(http, event).await? {
        CurrentEventAuthoringGeneration::Active(generation) => Ok(generation),
        CurrentEventAuthoringGeneration::Quarantine(reason) => anyhow::bail!(reason),
    }
}

pub(crate) enum CurrentEventAuthoringGeneration {
    Active(AuthoringGeneration),
    Quarantine(String),
}

pub(crate) async fn resolve_current_event_authoring_generation(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<CurrentEventAuthoringGeneration> {
    let authority_principal = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .as_str();
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured for generation-fenced write")
    })?;
    let device_id = signer.device_id().ok_or_else(|| {
        anyhow::anyhow!("active signer has no device_id for generation-fenced write")
    })?;
    let controller_generation =
        match resolve_principal_authoring_generation(http, authority_principal, device_id).await? {
            PrincipalGenerationResolution::Active(generation) => generation,
            PrincipalGenerationResolution::Quarantine(reason) => {
                return Ok(CurrentEventAuthoringGeneration::Quarantine(reason));
            }
        };
    cache_verified_principal_generation(authority_principal, device_id, &controller_generation);

    if event.executed_by.is_some() && authority_principal != event.actor_id.as_str() {
        return AuthoringGeneration::managed_agent(
            authority_principal,
            &controller_generation,
            event.authorization_ref.as_deref().unwrap_or_default(),
        )
        .map(CurrentEventAuthoringGeneration::Active)
        .map_err(anyhow::Error::from);
    }
    Ok(CurrentEventAuthoringGeneration::Active(
        controller_generation,
    ))
}

enum PrincipalGenerationResolution {
    Active(AuthoringGeneration),
    Quarantine(String),
}

async fn resolve_principal_authoring_generation(
    http: &arkret_sdk::http_client::Client,
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<PrincipalGenerationResolution> {
    let outcome = crate::transport::keys::query_keys(http, principal_id, device_id).await?;
    let principal = arkret_sdk::Did::new(principal_id.to_owned())?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let record = outcome
        .device_keys
        .get(&principal)
        .and_then(|devices| devices.get(&device));

    let b_generation = outcome.device_generations.get(&principal);
    let a_generation = outcome.cross_signing.get(&principal);
    match (a_generation, b_generation) {
        (Some(_), Some(_)) => Ok(PrincipalGenerationResolution::Quarantine(
            "authority_model_conflict".to_owned(),
        )),
        (None, Some(generation)) => {
            if generation.device_generation_status
                != arkret_sdk::models::DeviceGenerationStatus::Active
            {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "device_generation_conflicted".to_owned(),
                ));
            }
            let Some(record) = record else {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            };
            if record.device_status != Some(arkret_sdk::models::DeviceStatus::Active) {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            }
            let authorized_generation = record
                .authorized_generation_ref
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("B-model device omits authorized_generation_ref"))?;
            if authorized_generation != &generation.current_device_generation_ref {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_generation_superseded".to_owned(),
                ));
            }
            let binding = record
                .enrollment_authority_binding
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("B-model device omits enrollment_authority_binding")
                })?;
            if binding.authority_did.as_str() == principal_id {
                anyhow::bail!(
                    "self authority cannot be projected as an enrollment-authority generation"
                );
            }
            Ok(PrincipalGenerationResolution::Active(AuthoringGeneration {
                authority_model: AuthoringAuthorityModel::EnrollmentAuthority,
                authority_principal_id: principal_id.to_owned(),
                generation_ref: generation.current_device_generation_ref.as_str().to_owned(),
            }))
        }
        (Some(publish), None) => {
            let Some(record) = record else {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            };
            if record.device_status != Some(arkret_sdk::models::DeviceStatus::Active) {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            }
            if record.authorized_generation_ref.is_some()
                || record
                    .enrollment_authority_binding
                    .as_ref()
                    .is_some_and(|binding| binding.authority_did.as_str() != principal_id)
            {
                anyhow::bail!("cross-signing projection contains B-model authority state");
            }
            let binding = record
                .cross_signing_binding
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("A-model device omits cross_signing_binding"))?;
            if binding.ssk_generation != publish.generation.get() {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_generation_superseded".to_owned(),
                ));
            }
            Ok(PrincipalGenerationResolution::Active(AuthoringGeneration {
                authority_model: AuthoringAuthorityModel::CrossSigning,
                authority_principal_id: principal_id.to_owned(),
                generation_ref: format!("cross-signing:{}", publish.generation),
            }))
        }
        (None, None) => Ok(PrincipalGenerationResolution::Quarantine(
            "authority_generation_unknown".to_owned(),
        )),
    }
}

pub(crate) struct ResolvedQueueGenerationFence {
    decisions: BTreeMap<String, OutboundGenerationFenceDecision>,
}

impl ResolvedQueueGenerationFence {
    pub(crate) fn new(decisions: BTreeMap<String, OutboundGenerationFenceDecision>) -> Self {
        Self { decisions }
    }
}

impl OutboundGenerationFence for ResolvedQueueGenerationFence {
    fn evaluate(
        &self,
        item: &arkret_sdk::sync_client::SendQueueItem,
    ) -> arkret_sdk::Result<OutboundGenerationFenceDecision> {
        let queued: super::super::event_submit::QueuedSdkEvent =
            serde_json::from_value(item.content.clone()).map_err(|error| {
                arkret_sdk::Error::Protocol(format!(
                    "decode generation-fenced Inkson SDK event: {error}"
                ))
            })?;
        let decision = self.decisions.get(&item.transaction_id).ok_or_else(|| {
            arkret_sdk::Error::Protocol(format!(
                "generation fence omitted transaction {}",
                item.transaction_id
            ))
        })?;
        match decision {
            OutboundGenerationFenceDecision::Current => {
                let _ = queued;
                Ok(OutboundGenerationFenceDecision::Current)
            }
            OutboundGenerationFenceDecision::Quarantine { reason } => {
                Ok(OutboundGenerationFenceDecision::Quarantine {
                    reason: reason.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_generation_binds_controller_generation_and_delegation() {
        let controller = AuthoringGeneration {
            authority_model: AuthoringAuthorityModel::EnrollmentAuthority,
            authority_principal_id: "did:webvh:example:alice".to_owned(),
            generation_ref: "2-QmCurrent".to_owned(),
        };
        let first = AuthoringGeneration::managed_agent(
            "did:webvh:example:alice",
            &controller,
            "did:webvh:example:agent#controller",
        )
        .unwrap();
        let second = AuthoringGeneration::managed_agent(
            "did:webvh:example:alice",
            &controller,
            "did:webvh:example:agent#different-controller",
        )
        .unwrap();
        assert_eq!(first.authority_model, AuthoringAuthorityModel::ManagedAgent);
        assert_ne!(first.generation_ref, second.generation_ref);
    }
}
