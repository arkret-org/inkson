//! The MLS send gate of one effective scope.
//!
//! A Realm or Circle scope is plaintext until its own accepted
//! `ak.mls.genesis` and irreversibly standard RFC 9420 afterwards. The only
//! client-side evidence of that state is the Station's typed `mls_group`
//! current result, read from the durable current index at a complete verified
//! cut (encryption-and-audit §2.5.2 / §2.5.3). Nothing here infers activation
//! from Realm stream Events, an in-memory view or a local default: an
//! incomplete cut is "not ready", never "plaintext".

use crate::runtime::input::StateStoreHandle;
use crate::state::current_index::CurrentIndexLocation;
use crate::state::{CurrentIndex, LocalStateStore};

/// What the durable accepted current allows this device to send into a scope.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum MlsSendGate {
    /// The complete verified cut has no `mls_group` for the scope: it has no
    /// accepted Genesis, so application content is plaintext.
    Plaintext,
    /// The scope has an accepted Genesis, its key-access checkpoint is covered
    /// by the winning Commit, and this device's installed group sits exactly at
    /// that current state.
    Encrypted(arkret_wire::MlsGroupCurrent),
}

/// Why the gate cannot open for a new application body yet.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MlsSendGateBlocked {
    /// The durable current of the Realm is not a complete verified cut, so
    /// the scope's MLS state is unknown. Never collapses into plaintext.
    #[error("MLS send gate is not ready: {0}")]
    NotReady(String),
    /// This device holds a local group for the scope but the Station has not
    /// accepted its Genesis yet; plaintext would contradict the activation
    /// already begun.
    #[error("MLS send gate is not ready: the scope's MLS Genesis is not accepted yet")]
    GenesisPending,
    /// The current key-access revision is not covered by a winning Commit
    /// (`epoch_update_required`); encrypted sends pause.
    #[error("epoch_update_required: the scope key-access revision is not yet covered")]
    EpochUpdateRequired,
    /// The scope is activated but this device has no installed group at the
    /// current epoch and group-state reference.
    #[error(
        "MLS send gate is not ready: the local group is not at the accepted epoch {current_epoch}"
    )]
    LocalGroupBehind { current_epoch: u64 },
    /// Plaintext into an activated scope.
    #[error("mls_activation_required: plaintext is not allowed after MLS activation")]
    ActivationRequired,
    /// Ciphertext into a scope with no accepted Genesis.
    #[error("the scope has no accepted MLS group, so it carries no ciphertext")]
    NotActivated,
    /// The body's frozen epoch or group-state reference is not the current one.
    #[error("epoch_mismatch: the frozen encryption context is no longer current")]
    EpochMismatch,
}

/// This device's installed group state for a scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalMlsGroup {
    pub epoch: u64,
    pub group_state_ref: Option<arkret_sdk::EventId>,
}

/// Everything the gate needs from the account store. The installed group is
/// captured synchronously; the committed current generation is read again
/// under the index lease, because a frame committed while the gate waits for
/// that lease moves it.
#[derive(Clone)]
pub(crate) struct MlsSendGateInput {
    store: StateStoreHandle,
    authority: Option<arkret_sdk::AccountId>,
    location: CurrentIndexLocation,
    local: Option<LocalMlsGroup>,
}

impl MlsSendGateInput {
    pub(crate) fn capture(store: &StateStoreHandle, scope: &arkret_sdk::ScopeRef) -> Self {
        store.read(|state: &LocalStateStore| {
            let local = state.mls_checkpoint_for_scope(scope).map(|checkpoint| {
                let group_state_ref = state
                    .mls_group_state_ref_for_scope(scope, &checkpoint.group_id, checkpoint.epoch)
                    .ok();
                LocalMlsGroup {
                    epoch: checkpoint.epoch,
                    group_state_ref,
                }
            });
            Self {
                store: store.clone(),
                authority: state.active_authority(),
                location: state.current_index_location(),
                local,
            }
        })
    }
}

/// Read the scope's accepted `mls_group` from the durable current index at a
/// complete verified cut. `Ok(None)` is that cut's answer; every missing
/// precondition is an error.
async fn read_durable_mls_current(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
) -> anyhow::Result<Option<arkret_wire::MlsGroupCurrent>> {
    let authority = input
        .authority
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no active account current index"))?;
    let index = CurrentIndex::open_committed(authority, input.location.clone(), || {
        input.store.read(|state| {
            anyhow::ensure!(
                state.active_authority().as_ref() == Some(authority),
                "the active account changed before the send gate read its current"
            );
            anyhow::ensure!(
                !state.current_reset_required(),
                "the account current index awaits a fresh baseline"
            );
            Ok(state.current_generation())
        })
    })
    .await?;
    index
        .read_mls_group_ready(scope, &arkret_sdk::ActorId::account(authority.clone()))
        .await
}

/// Decide the gate from the durable read and this device's installed group.
pub(crate) fn decide_mls_send_gate(
    current: anyhow::Result<Option<arkret_wire::MlsGroupCurrent>>,
    local: Option<&LocalMlsGroup>,
) -> Result<MlsSendGate, MlsSendGateBlocked> {
    let current = current.map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
    let Some(current) = current else {
        return match local {
            Some(_) => Err(MlsSendGateBlocked::GenesisPending),
            None => Ok(MlsSendGate::Plaintext),
        };
    };
    if current.covered_key_access_revision < current.current_key_access_revision {
        return Err(MlsSendGateBlocked::EpochUpdateRequired);
    }
    match local {
        Some(local)
            if local.epoch == current.epoch
                && local.group_state_ref.as_ref()
                    == Some(&current.current_mls_commit_event_ref) =>
        {
            Ok(MlsSendGate::Encrypted(current))
        }
        _ => Err(MlsSendGateBlocked::LocalGroupBehind {
            current_epoch: current.epoch,
        }),
    }
}

/// Resolve the gate of `scope` for a new application body.
pub(crate) async fn resolve_mls_send_gate(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
) -> Result<MlsSendGate, MlsSendGateBlocked> {
    let gate = decide_mls_send_gate(
        read_durable_mls_current(input, scope).await,
        input.local.as_ref(),
    )?;
    if let MlsSendGate::Encrypted(current) = &gate {
        let durable = input
            .store
            .read(|state| state.durable_mls_checkpoint_for_scope(scope))
            .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
        if durable.is_none_or(|snapshot| {
            snapshot.epoch != current.epoch
                || snapshot.group_state_event_id.as_ref()
                    != Some(&current.current_mls_commit_event_ref)
        }) {
            return Err(MlsSendGateBlocked::NotReady(
                "private MLS publication is not durably committed".into(),
            ));
        }
    }
    Ok(gate)
}

/// Readiness also requires that this endpoint can restore its private group.
/// This probe neither creates secrets nor advances a sender ratchet.
pub(crate) async fn resolve_restorable_mls_send_gate(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
    device: &arkret_sdk::DeviceId,
) -> anyhow::Result<MlsSendGate> {
    let gate = resolve_mls_send_gate(input, scope).await?;
    input.store.read(|state| {
        let realm_id = scope
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("scope has no Realm"))?;
        anyhow::ensure!(
            !state.realm_detail_invalidated(realm_id.as_str()),
            "the Realm detail awaits a complete baseline"
        );
        anyhow::ensure!(
            !state.current_reset_required() && state.active_authority() == input.authority,
            "the account current changed"
        );
        anyhow::ensure!(
            state.persist_error().is_none(),
            "local persistence has failed"
        );
        Ok::<_, anyhow::Error>(())
    })?;
    if let MlsSendGate::Encrypted(current) = &gate {
        let authority = input
            .authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active account"))?;
        let snapshot = input.store.read(|state| {
            anyhow::ensure!(
                state.active_authority().as_ref() == Some(authority),
                "active account changed"
            );
            state
                .durable_mls_checkpoint_for_scope(scope)?
                .ok_or_else(|| anyhow::anyhow!("private MLS group is not installed"))
        })?;
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let secret = crate::mls::runtime::load_device_checkpoint_secret(
            secure_store.as_ref(),
            authority,
            device,
        )?;
        let group = crate::mls::persistence::restore_envelope(&snapshot, &secret, current.epoch)?;
        anyhow::ensure!(
            group.scope() == scope && group.epoch() == current.epoch,
            "private MLS group does not match current"
        );
        anyhow::ensure!(
            group.local_actor_id() == &arkret_sdk::ActorId::account(authority.clone()),
            "private MLS actor does not match account"
        );
        anyhow::ensure!(
            group.local_endpoint_identity()
                == arkret_sdk::MlsEndpointIdentity::HumanDevice {
                    principal_id: authority.principal_id.clone(),
                    device_id: device.clone()
                },
            "private MLS endpoint does not match device"
        );
        group.local_content_sender_domain()?;
    }
    Ok(gate)
}

/// A retry keeps its original ciphertext and epoch. Recheck current Circle
/// qualification locally; the authority decides acceptance or exact replay.
pub(crate) async fn check_circle_send_membership(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
) -> Result<(), MlsSendGateBlocked> {
    read_durable_mls_current(input, scope)
        .await
        .map(|_| ())
        .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))
}

/// The encryption shape of one already built application body.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ApplicationBody {
    Plaintext,
    Encrypted(Vec<arkret_sdk::EncryptedEnvelope>),
}

impl ApplicationBody {
    /// The gated body of one Event, or `None` when the kind carries no
    /// application content the send gate governs.
    ///
    /// Message create and revise carry exactly one of `content` or
    /// `encrypted_content` (plus optional `encrypted_metadata`); both shapes
    /// are gated. A reaction is gated only when it carries an encrypted
    /// payload, because only then does it cite an epoch.
    pub(crate) fn of_event(
        kind: &arkret_sdk::EventKind,
        payload: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> anyhow::Result<Option<Self>> {
        let envelope = |field: &str| -> anyhow::Result<Option<arkret_sdk::EncryptedEnvelope>> {
            payload
                .get(field)
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()
                .map_err(|error| anyhow::anyhow!("{} {field}: {error}", kind.as_str()))
        };
        match kind {
            arkret_sdk::EventKind::MessageCreate | arkret_sdk::EventKind::MessageRevise => {
                let content = envelope("encrypted_content")?;
                let metadata = envelope("encrypted_metadata")?;
                Ok(Some(match (content, metadata) {
                    (Some(content), metadata) => {
                        Self::Encrypted(std::iter::once(content).chain(metadata).collect())
                    }
                    (None, None) => Self::Plaintext,
                    (None, Some(_)) => anyhow::bail!(
                        "{} encrypted_metadata requires encrypted_content",
                        kind.as_str()
                    ),
                }))
            }
            arkret_sdk::EventKind::ReactionAdd => {
                Ok(envelope("encrypted_payload")?.map(|payload| Self::Encrypted(vec![payload])))
            }
            _ => Ok(None),
        }
    }
}

/// Check an already built body against the durable accepted current, the same
/// way the governing Station's send gate does (§2.5.2): plaintext requires a
/// complete cut without an accepted Genesis, ciphertext requires the current
/// group with a covered key-access revision and the exact current epoch and
/// group-state reference.
pub(crate) async fn check_application_body(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
    body: ApplicationBody,
) -> Result<(), MlsSendGateBlocked> {
    check_application_body_against(
        read_durable_mls_current(input, scope).await,
        input.local.as_ref(),
        body,
    )
}

pub(crate) fn check_application_body_against(
    current: anyhow::Result<Option<arkret_wire::MlsGroupCurrent>>,
    local: Option<&LocalMlsGroup>,
    body: ApplicationBody,
) -> Result<(), MlsSendGateBlocked> {
    let current = current.map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
    match (body, current) {
        (ApplicationBody::Plaintext, Some(_)) => Err(MlsSendGateBlocked::ActivationRequired),
        (ApplicationBody::Plaintext, None) => match local {
            Some(_) => Err(MlsSendGateBlocked::GenesisPending),
            None => Ok(()),
        },
        (ApplicationBody::Encrypted(_), None) => Err(MlsSendGateBlocked::NotActivated),
        (ApplicationBody::Encrypted(envelopes), Some(current)) => {
            if current.covered_key_access_revision < current.current_key_access_revision {
                return Err(MlsSendGateBlocked::EpochUpdateRequired);
            }
            let stale = envelopes.iter().any(|envelope| {
                envelope.encryption_context.epoch() != current.epoch
                    || envelope.encryption_context.group_state_ref()
                        != &current.current_mls_commit_event_ref
            });
            if stale {
                return Err(MlsSendGateBlocked::EpochMismatch);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        }
    }

    fn event(seed: u8) -> arkret_sdk::EventId {
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [seed; 32])
    }

    fn current(epoch: u64, current_revision: u64, covered: u64) -> arkret_wire::MlsGroupCurrent {
        arkret_wire::MlsGroupCurrent {
            effective_scope: scope(),
            genesis_event_ref: event(1),
            current_mls_commit_event_ref: event(2),
            epoch,
            current_key_access_revision: current_revision,
            covered_key_access_revision: covered,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "33".repeat(32)
            ))
            .unwrap(),
        }
    }

    fn local(epoch: u64, seed: u8) -> LocalMlsGroup {
        LocalMlsGroup {
            epoch,
            group_state_ref: Some(event(seed)),
        }
    }

    #[test]
    fn an_incomplete_cut_is_not_ready_rather_than_plaintext() {
        let gate = decide_mls_send_gate(Err(anyhow::anyhow!("no baseline")), None);
        assert!(matches!(gate, Err(MlsSendGateBlocked::NotReady(_))));
        let body = check_application_body_against(
            Err(anyhow::anyhow!("no baseline")),
            None,
            ApplicationBody::Plaintext,
        );
        assert!(matches!(body, Err(MlsSendGateBlocked::NotReady(_))));
    }

    #[test]
    fn a_complete_cut_without_mls_group_is_plaintext() {
        assert_eq!(
            decide_mls_send_gate(Ok(None), None),
            Ok(MlsSendGate::Plaintext)
        );
        assert_eq!(
            check_application_body_against(Ok(None), None, ApplicationBody::Plaintext),
            Ok(())
        );
    }

    #[test]
    fn a_local_group_without_accepted_genesis_blocks_plaintext() {
        assert_eq!(
            decide_mls_send_gate(Ok(None), Some(&local(0, 2))),
            Err(MlsSendGateBlocked::GenesisPending)
        );
        assert_eq!(
            check_application_body_against(
                Ok(None),
                Some(&local(0, 2)),
                ApplicationBody::Plaintext
            ),
            Err(MlsSendGateBlocked::GenesisPending)
        );
    }

    #[test]
    fn an_activated_scope_encrypts_only_at_the_exact_current_state() {
        assert_eq!(
            decide_mls_send_gate(Ok(Some(current(3, 1, 1))), Some(&local(3, 2))),
            Ok(MlsSendGate::Encrypted(current(3, 1, 1)))
        );
        assert_eq!(
            decide_mls_send_gate(Ok(Some(current(3, 1, 1))), Some(&local(2, 2))),
            Err(MlsSendGateBlocked::LocalGroupBehind { current_epoch: 3 })
        );
        assert_eq!(
            decide_mls_send_gate(Ok(Some(current(3, 1, 1))), Some(&local(3, 9))),
            Err(MlsSendGateBlocked::LocalGroupBehind { current_epoch: 3 })
        );
        assert_eq!(
            decide_mls_send_gate(Ok(Some(current(3, 1, 1))), None),
            Err(MlsSendGateBlocked::LocalGroupBehind { current_epoch: 3 })
        );
        assert_eq!(
            decide_mls_send_gate(Ok(Some(current(3, 2, 1))), Some(&local(3, 2))),
            Err(MlsSendGateBlocked::EpochUpdateRequired)
        );
    }

    #[test]
    fn only_message_content_and_encrypted_reactions_are_gated() {
        use serde_json::json;
        let payload = |value: serde_json::Value| {
            value
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let message = payload(json!({"strand_id": "s", "track_name": "t", "content": {}}));
        assert_eq!(
            ApplicationBody::of_event(&arkret_sdk::EventKind::MessageCreate, &message).unwrap(),
            Some(ApplicationBody::Plaintext)
        );
        assert_eq!(
            ApplicationBody::of_event(&arkret_sdk::EventKind::MessageRevise, &message).unwrap(),
            Some(ApplicationBody::Plaintext)
        );
        let reaction = payload(json!({"target_ref": "e", "key": "+1"}));
        assert_eq!(
            ApplicationBody::of_event(&arkret_sdk::EventKind::ReactionAdd, &reaction).unwrap(),
            None
        );
        assert_eq!(
            ApplicationBody::of_event(&arkret_sdk::EventKind::MemberState, &message).unwrap(),
            None
        );
        let metadata_only = payload(json!({"encrypted_metadata": {}}));
        assert!(
            ApplicationBody::of_event(&arkret_sdk::EventKind::MessageCreate, &metadata_only)
                .is_err()
        );
    }

    #[test]
    fn plaintext_into_an_activated_scope_is_activation_required() {
        assert_eq!(
            check_application_body_against(
                Ok(Some(current(0, 0, 0))),
                None,
                ApplicationBody::Plaintext
            ),
            Err(MlsSendGateBlocked::ActivationRequired)
        );
        assert_eq!(
            check_application_body_against(Ok(None), None, ApplicationBody::Encrypted(Vec::new())),
            Err(MlsSendGateBlocked::NotActivated)
        );
    }
}
