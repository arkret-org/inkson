//! Durable outbound authoring-generation fence.
//!
//! A queued Event is bound to the verified device authority generation that
//! authored it. Before every replay the current keys projection is fetched
//! again and compared exactly. Recovery therefore cannot accidentally revive
//! queued work signed by an old device generation or a controller generation that no longer
//! authorizes a Agent write.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

/// Which authority a queued write was authored under.
///
/// This is holder-local queue vocabulary, not a wire shape: it never leaves the
/// device and nothing on the authority protocol reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthoringAuthorityModel {
    /// A device accepted by its own principal's current device generation.
    AcceptedDevice,
    /// An Agent authoring on a controller's behalf.
    Agent,
}

/// The exact authoring authority a queued Event was signed under.
///
/// A replay compares this against the freshly fetched keys projection, so a
/// queued write can never be revived under a superseded device generation or a
/// delegation the controller has since withdrawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthoringGeneration {
    pub(crate) authority_model: AuthoringAuthorityModel,
    pub(crate) authority_principal_id: arkret_sdk::DidCoreId,
    pub(crate) generation_ref: String,
}

impl AuthoringGeneration {
    /// Derive the delegated generation an Agent write is fenced by.
    ///
    /// It binds both the controller's own current generation and the exact
    /// delegation the write claims, so withdrawing either one invalidates every
    /// queued Agent write authored under it.
    pub(crate) fn agent(
        authority_principal_id: &str,
        controller: &Self,
        authorization_ref: &str,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !authorization_ref.is_empty(),
            "a delegated authoring generation requires the authorization it claims"
        );
        let binding = serde_json::json!({
            "authority_principal_id": authority_principal_id,
            "controller_principal_id": controller.authority_principal_id.as_str(),
            "controller_generation_ref": controller.generation_ref,
            "authorization_ref": authorization_ref,
        });
        Ok(Self {
            authority_model: AuthoringAuthorityModel::Agent,
            authority_principal_id: arkret_sdk::DidCoreId::new(authority_principal_id.to_owned())?,
            generation_ref: crate::canonical::canonical_sha256(&binding)?,
        })
    }
}

/// What the replay fence decided about one durably queued item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GenerationFenceDecision {
    /// The authoring generation still holds; the item may be forwarded.
    Current,
    /// The authoring generation is gone; the item must not be forwarded.
    Quarantine { reason: String },
}

fn verified_generation_cache() -> &'static Mutex<BTreeMap<String, AuthoringGeneration>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, AuthoringGeneration>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn principal_generation_cache_key(account_id: &arkret_sdk::AccountId, device_id: &str) -> String {
    format!("{account_id}\u{1f}{device_id}")
}

pub(crate) fn cache_verified_principal_generation(
    account_id: &arkret_sdk::AccountId,
    device_id: &str,
    generation: &AuthoringGeneration,
) {
    let previous = verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            principal_generation_cache_key(account_id, device_id),
            generation.clone(),
        );
    if previous.as_ref().is_some_and(|value| value != generation) {}
}

#[cfg(test)]
pub(crate) fn cache_verified_principal_generation_for_test(
    principal_id: &str,
    device_id: &str,
    generation_ref: &str,
) {
    cache_verified_principal_generation(
        &arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(principal_id.to_owned()).unwrap(),
            crate::operation::authoring_station_id().unwrap(),
        ),
        device_id,
        &AuthoringGeneration {
            authority_model: AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: arkret_sdk::DidCoreId::new(principal_id.to_owned())
                .expect("test principal_id must be valid"),
            generation_ref: generation_ref.to_owned(),
        },
    );
}

pub(crate) fn reset_verified_authoring_generations() {
    verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

/// Return the exact accepted device-generation fence cached for one endpoint.
/// Minimal-metadata pairwise identities bind their KDF to this incarnation;
/// using only the stable DeviceId would silently reuse an actor after a
/// reinstall or generation replacement.
pub(crate) fn cached_principal_authoring_generation(
    account_id: &arkret_sdk::AccountId,
    device_id: &str,
) -> Option<AuthoringGeneration> {
    verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&principal_generation_cache_key(account_id, device_id))
        .cloned()
}

/// The envelope facts a generation fence needs, readable from either side of
/// the authoring boundary.
///
/// Nothing here depends on `event_id`, which is why the fence can run on a
/// frozen intent as well as on an authored Event — and why it never needed an
/// Event to be authored early just to answer this question.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EventAuthorityFacts<'a> {
    actor_id: &'a arkret_sdk::ActorId,
    executed_by: Option<&'a arkret_sdk::ActorId>,
    authorization_ref: Option<&'a arkret_sdk::AuthorizationRef>,
}

impl<'a> EventAuthorityFacts<'a> {
    fn authority_account(&self) -> anyhow::Result<&arkret_sdk::AccountId> {
        self.executed_by
            .unwrap_or(self.actor_id)
            .as_account_id()
            .ok_or_else(|| {
                anyhow::anyhow!("device authoring generation requires an exact account actor")
            })
    }
    pub(crate) fn from_intent(intent: &'a crate::operation::EventIntent) -> Self {
        Self {
            actor_id: intent.actor_id(),
            executed_by: intent.executed_by(),
            authorization_ref: intent.authorization_ref(),
        }
    }

    /// The principal whose device generation authorizes this write.
    fn authority_principal(&self) -> &str {
        self.executed_by
            .unwrap_or(self.actor_id)
            .signing_principal_id()
            .as_str()
    }

    /// True when a Agent authors on a controller's behalf.
    fn is_delegated(&self) -> bool {
        self.executed_by
            .is_some_and(|executed_by| executed_by != self.actor_id)
    }

    fn authorization_ref_str(&self) -> &str {
        self.authorization_ref
            .map(|value| value.as_str())
            .unwrap_or_default()
    }
}

pub(crate) fn cached_event_authoring_generation(
    facts: &EventAuthorityFacts<'_>,
) -> anyhow::Result<Option<AuthoringGeneration>> {
    let authority_principal = facts.authority_principal();
    let account_id = facts.authority_account()?;
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured for generation-fenced write")
    })?;
    let device_id = signer.device_id().ok_or_else(|| {
        anyhow::anyhow!("active signer has no device_id for generation-fenced write")
    })?;
    let Some(controller_generation) = verified_generation_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&principal_generation_cache_key(account_id, device_id))
        .cloned()
    else {
        return Ok(None);
    };

    if facts.is_delegated() {
        return AuthoringGeneration::agent(
            authority_principal,
            &controller_generation,
            facts.authorization_ref_str(),
        )
        .map(Some)
        .map_err(anyhow::Error::from);
    }
    Ok(Some(controller_generation))
}

pub(crate) async fn resolve_event_authoring_generation(
    _http: &arkret_sdk::http_client::Client,
    facts: &EventAuthorityFacts<'_>,
) -> anyhow::Result<AuthoringGeneration> {
    cached_event_authoring_generation(facts)?.ok_or_else(|| {
        anyhow::anyhow!(
            "frontier_unavailable: no locally verified device authoring authority is available"
        )
    })
}

enum PrincipalGenerationResolution {
    Active(AuthoringGeneration),
    Quarantine(String),
}

/// Cache the current authoring generation from a keys projection that the
/// authenticated connection bootstrap has already fetched. Returning `false`
/// keeps the device-authorization gate closed when the projection quarantines
/// the device, so offline submission can never fall back to an unverified
/// generation after a full-page WASM reload.
pub(crate) fn cache_principal_authoring_generation_from_keys(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device_id: &str,
) -> anyhow::Result<bool> {
    match resolve_principal_authoring_generation_from_keys(outcome, account_id, device_id)? {
        PrincipalGenerationResolution::Active(generation) => {
            cache_verified_principal_generation(account_id, device_id, &generation);
            Ok(true)
        }
        PrincipalGenerationResolution::Quarantine(reason) => {
            tracing::warn!(%reason, "device authoring generation is quarantined");
            verified_generation_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&principal_generation_cache_key(account_id, device_id));
            Ok(false)
        }
    }
}

fn resolve_principal_authoring_generation_from_keys(
    outcome: &arkret_models_crypto::KeysQueryOutcome,
    account_id: &arkret_sdk::AccountId,
    device_id: &str,
) -> anyhow::Result<PrincipalGenerationResolution> {
    account_id.validate()?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned())?;
    let record = outcome
        .devices_for(account_id)
        .and_then(|devices| devices.get(&device));

    match outcome.generation_for(account_id) {
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
            // The row was read at the exact `(account_id, device)` selectors, so
            // the Station-verified projection is bound to this account and
            // device; what is left to check is the row's own usability.
            let Ok(attested) = crate::identity::device_directory::validate_self_device_row(record)
            else {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_projection_unusable".to_owned(),
                ));
            };
            if !crate::identity::device_directory::projection_authorization_window_contains(
                attested,
                chrono::Utc::now(),
            ) {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_device_not_active".to_owned(),
                ));
            }
            if attested.authorized_generation_ref != generation.current_device_generation_ref {
                return Ok(PrincipalGenerationResolution::Quarantine(
                    "authoring_generation_superseded".to_owned(),
                ));
            }
            Ok(PrincipalGenerationResolution::Active(AuthoringGeneration {
                authority_model: AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: account_id.principal_id.clone(),
                generation_ref: generation.current_device_generation_ref.to_string(),
            }))
        }
        None => Ok(PrincipalGenerationResolution::Quarantine(
            "authority_generation_unknown".to_owned(),
        )),
    }
}

/// Per-item replay decisions resolved once for a whole drain pass.
pub(crate) struct ResolvedQueueGenerationFence {
    decisions: BTreeMap<arkret_sdk::EventId, GenerationFenceDecision>,
}

impl ResolvedQueueGenerationFence {
    pub(crate) fn new(decisions: BTreeMap<arkret_sdk::EventId, GenerationFenceDecision>) -> Self {
        Self { decisions }
    }

    /// The decision for one queued submission.
    ///
    /// A queued item with no resolved decision fails closed: the drain pass
    /// resolves every item it is about to forward, so a missing entry means the
    /// queue changed under the pass rather than that the item is current.
    pub(crate) fn evaluate(
        &self,
        item: &garth::SendQueueItem,
    ) -> anyhow::Result<&GenerationFenceDecision> {
        self.decisions.get(item.event_id()).ok_or_else(|| {
            anyhow::anyhow!(
                "generation fence omitted queued Event {}",
                item.event_id().as_str()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_cache_does_not_cross_station_accounts() {
        let principal =
            arkret_sdk::DidCoreId::new("ak:did_core:web:cache-account.example").unwrap();
        let first = arkret_sdk::AccountId::new(
            principal.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:first.example").unwrap(),
        );
        let second = arkret_sdk::AccountId::new(
            principal.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:second.example").unwrap(),
        );
        let generation = AuthoringGeneration {
            authority_model: AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: principal,
            generation_ref: "7".to_owned(),
        };
        cache_verified_principal_generation(&first, "device-cache-test", &generation);
        assert_eq!(
            cached_principal_authoring_generation(&first, "device-cache-test"),
            Some(generation)
        );
        assert!(cached_principal_authoring_generation(&second, "device-cache-test").is_none());
    }

    #[test]
    fn active_generation_projects_a_resolvable_principal_did_to_its_core_id() {
        let principal_did = "did:webvh:QmR4AHvRgux4GsojV8fkDVxjHWsJkFqDnV6SFCwDRGCE8u:soland.local.host%3A23452:webvh:01a04bf8-ad5b-7165-9691-45793fe99362";
        let principal = crate::mls_api_helpers::principal_core_id(principal_did).unwrap();
        let account_id = arkret_sdk::AccountId::new(principal.clone(), principal.clone());
        let device =
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        // The self row carries the Station-verified projection plus the
        // reference later Events actually use; no origin proof shell reaches
        // the client, and the projection repeats neither account nor device.
        let record: arkret_models_crypto::QueryDeviceRecord = serde_json::from_value(
            serde_json::json!({
                "signer_evidence_ref":
                    "ak:signer_evidence:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "algorithms": {},
                "trust_algorithms": [],
                "device_projection": {
                    "device_signing_key_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
                    "hpke_key": "hpke-1",
                    "device_authorize_event_id": "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
                    "authorized_generation_ref": 7,
                    "device_status": "active",
                    "authorization_window": {
                        "not_before": "2026-08-15T00:00:00.000Z",
                        "expires_at": null
                    },
                    "attested_at": "2026-08-15T00:00:00.000Z",
                    "expires_at": "2026-08-15T00:10:00.000Z"
                }
            }),
        )
        .unwrap();
        let outcome = arkret_models_crypto::KeysQueryOutcome {
            device_keys: vec![arkret_models_crypto::QueryAccountDeviceEntry {
                account_id: account_id.clone(),
                device_keys: BTreeMap::from([(device.clone(), record)]),
            }],
            failures: Vec::new(),
            device_generations: vec![arkret_models_crypto::AccountDeviceGenerationEntry {
                account_id: account_id.clone(),
                generation_state: arkret_models_crypto::DeviceGenerationState {
                    current_device_generation_ref: 7,
                    device_generation_status: arkret_models_crypto::DeviceGenerationStatus::Active,
                },
            }],
        };

        let resolution = resolve_principal_authoring_generation_from_keys(
            &outcome,
            &account_id,
            device.as_str(),
        )
        .unwrap();
        let PrincipalGenerationResolution::Active(generation) = resolution else {
            panic!("active projection must resolve an authoring generation");
        };
        assert_eq!(generation.authority_principal_id, principal);
    }

    #[test]
    fn managed_generation_binds_controller_generation_and_delegation() {
        let controller = AuthoringGeneration {
            authority_model: AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:example".to_owned(),
            )
            .unwrap(),
            generation_ref: "2-QmCurrent".to_owned(),
        };
        let first = AuthoringGeneration::agent(
            "ak:did_core:webvh:example",
            &controller,
            "did:webvh:example:agent#controller",
        )
        .unwrap();
        let second = AuthoringGeneration::agent(
            "ak:did_core:webvh:example",
            &controller,
            "did:webvh:example:agent#different-controller",
        )
        .unwrap();
        assert_eq!(first.authority_model, AuthoringAuthorityModel::Agent);
        assert_ne!(first.generation_ref, second.generation_ref);
    }
}
