//! Durable outbound authoring-generation fence.
//!
//! A queued Event is bound to the verified device authority generation that
//! authored it. Before every replay the current keys projection is fetched
//! again and compared exactly. Recovery therefore cannot accidentally revive
//! queued work signed by an old device generation or a controller generation that no longer
//! authorizes a managed Agent write.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

pub(crate) use garth::{AuthoringAuthorityModel, AuthoringGeneration};
use garth::{OutboundGenerationFence, OutboundGenerationFenceDecision};

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
    let previous = verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            principal_generation_cache_key(principal_id, device_id),
            generation.clone(),
        );
    if previous.as_ref().is_some_and(|value| value != generation) {
        crate::authorization_lease::clear_leases();
    }
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
    resolve_principal_authoring_generation_from_keys(&outcome, principal_id, device_id)
}

/// Cache the current authoring generation from a keys projection that the
/// authenticated connection bootstrap has already fetched. Returning `false`
/// keeps the device-authorization gate closed when the projection quarantines
/// the device, so offline submission can never fall back to an unverified
/// generation after a full-page WASM reload.
pub(crate) fn cache_principal_authoring_generation_from_keys(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<bool> {
    match resolve_principal_authoring_generation_from_keys(outcome, principal_id, device_id)? {
        PrincipalGenerationResolution::Active(generation) => {
            cache_verified_principal_generation(principal_id, device_id, &generation);
            Ok(true)
        }
        PrincipalGenerationResolution::Quarantine(_) => Ok(false),
    }
}

fn resolve_principal_authoring_generation_from_keys(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    principal_id: &str,
    device_id: &str,
) -> anyhow::Result<PrincipalGenerationResolution> {
    let principal = crate::mls_api_helpers::principal_core_id(principal_id)?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let record = outcome
        .device_keys
        .get(&principal)
        .and_then(|devices| devices.get(&device));

    match outcome.device_generations.get(&principal) {
        Some(generation) => {
            if generation.device_generation_status
                != arkret_models_crypto::DeviceGenerationStatus::Active
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
            if record.device_status != arkret_models_crypto::DeviceStatus::Active {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            }
            if record.authorized_generation_ref != generation.current_device_generation_ref {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_generation_superseded".to_owned(),
                ));
            }
            Ok(PrincipalGenerationResolution::Active(AuthoringGeneration {
                authority_model: AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: principal_id.to_owned(),
                generation_ref: generation.current_device_generation_ref.to_string(),
            }))
        }
        None => Ok(PrincipalGenerationResolution::Quarantine(
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
        item: &garth::SendQueueItem,
    ) -> garth::Result<OutboundGenerationFenceDecision> {
        let garth::QueuedRecord::SdkEvent(queued) = &item.record else {
            return Ok(OutboundGenerationFenceDecision::Current);
        };
        let decision = self.decisions.get(&item.transaction_id).ok_or_else(|| {
            garth::Error::Protocol(format!(
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
            authority_model: AuthoringAuthorityModel::AcceptedDevice,
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
