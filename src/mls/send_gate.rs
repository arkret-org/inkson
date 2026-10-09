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
pub(crate) async fn read_durable_mls_current(
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

/// A durable local MLS choice blocks plaintext before there is any epoch-zero
/// material. It is a local safety fence, never an activation claim about a peer.
pub(crate) async fn check_creator_plaintext_slot(
    store: &crate::outbound_store::InksonOutboundStore,
    scope: &arkret_sdk::ScopeRef,
) -> Result<(), MlsSendGateBlocked> {
    if store
        .has_creator_intent_for_scope(scope)
        .await
        .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?
    {
        return Err(MlsSendGateBlocked::GenesisPending);
    }
    Ok(())
}

async fn check_local_creator_plaintext_fence(
    input: &MlsSendGateInput,
    scope: &arkret_sdk::ScopeRef,
) -> Result<(), MlsSendGateBlocked> {
    let authority = input
        .authority
        .as_ref()
        .ok_or_else(|| MlsSendGateBlocked::NotReady("no active authoring vault".into()))?;
    let store = crate::outbound_store::InksonOutboundStore::open(
        authority,
        crate::outbound_store::OutboundLane::Standard,
    )
    .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
    check_creator_plaintext_slot(&store, scope).await
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
    if gate == MlsSendGate::Plaintext {
        check_local_creator_plaintext_fence(input, scope).await?;
    }
    if let MlsSendGate::Encrypted(current) = &gate {
        let authority = input
            .authority
            .as_ref()
            .ok_or_else(|| MlsSendGateBlocked::NotReady("no active authoring vault".into()))?;
        let vault = crate::outbound_store::InksonOutboundStore::open(
            authority,
            crate::outbound_store::OutboundLane::Standard,
        )
        .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
        let terminal = vault
            .check_creator_ready_slot(scope, &current.genesis_event_ref)
            .await
            .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
        let durable = input
            .store
            .read(|state| state.durable_mls_checkpoint_for_scope(scope))
            .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
        if durable.as_ref().is_none_or(|snapshot| {
            snapshot.epoch != current.epoch
                || snapshot.group_state_event_id.as_ref()
                    != Some(&current.current_mls_commit_event_ref)
        }) {
            return Err(MlsSendGateBlocked::NotReady(
                "private MLS publication is not durably committed".into(),
            ));
        }
        if let Some(record) = terminal {
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if record.ready_receipt().is_some() {
                crate::event_submit::original_creator_checkpoint_secret(
                    &record,
                    secure_store.as_ref(),
                    authority,
                )
                .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
            }
            let secret = crate::mls::runtime::load_device_checkpoint_secret(
                secure_store.as_ref(),
                authority,
                record.intent().creator_device_id(),
            )
            .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
            let snapshot = durable.as_ref().ok_or_else(|| {
                MlsSendGateBlocked::NotReady("winning private state is not installed".into())
            })?;
            let private_check = (|| -> anyhow::Result<()> {
                if record.ready_receipt().is_some() {
                    let restored = crate::event_submit::restored_creator_artifacts(
                        &record,
                        secure_store.as_ref(),
                        authority,
                    )?;
                    anyhow::ensure!(
                        record.artifacts() == Some(&restored),
                        "ready creator recovery unit differs from its durable artifacts"
                    );
                }
                let group =
                    crate::mls::persistence::restore_envelope(snapshot, &secret, current.epoch)?;
                if record.superseded_winner().is_some() {
                    validate_superseded_private_group(&record, &group, current)
                } else {
                    validate_ready_creator_private_group(&record, &group, current)
                }
            })();
            if let Err(error) = private_check {
                #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
                tracing::warn!(error = %error, "creator private material verification failed");
                // A superseded original cannot be amended. Its separately
                // acquired winner cache remains blocked when inconsistent.
                if record.ready_receipt().is_some() {
                    use arkret_models_collaboration::mls_creator_bootstrap::{
                        MlsCreatorBootstrapInvariant, MlsCreatorBootstrapKnownGenesis,
                    };
                    let known = record.accepted_genesis().map(|accepted| {
                        MlsCreatorBootstrapKnownGenesis::Original {
                            acceptance: Box::new(accepted.clone()),
                        }
                    });
                    vault
                        .quarantine_creator(
                            record,
                            MlsCreatorBootstrapInvariant::PrivateMaterial,
                            error.to_string(),
                            known,
                        )
                        .await
                        .map_err(|error| MlsSendGateBlocked::NotReady(error.to_string()))?;
                }
                return Err(MlsSendGateBlocked::NotReady(error.to_string()));
            }
        }
    }
    Ok(gate)
}

/// A ready creator must still restore the accepted original or a later
/// durable private state bound to the authenticated current public tree.
pub(crate) fn validate_ready_creator_private_group(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    group: &arkret_sdk::ArkretMlsGroup,
    current: &arkret_wire::MlsGroupCurrent,
) -> anyhow::Result<()> {
    let accepted = record
        .accepted_genesis()
        .ok_or_else(|| anyhow::anyhow!("creator has no accepted original"))?;
    let (info, tree) = group.public_group_state_bytes()?;
    let digest = arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
        &current.public_tree_ref,
    )?
    .digest_suite()?;
    let reference = format!("ak:blob:{}", arkret_sdk::canonical::digest(digest, &tree));
    anyhow::ensure!(
        record.ready_receipt().is_some()
            && accepted.accepted().event.event_id == current.genesis_event_ref
            && group.scope() == record.intent().effective_scope()
            && group.scope() == &current.effective_scope
            && group.group_id() == *record.intent().mls_group_id()
            && group.epoch() == current.epoch
            && group.local_actor_id() == record.intent().owner_actor_id()
            && current.public_tree_ref.as_str() == reference,
        "creator private state differs from its accepted Genesis/current tree"
    );
    if group.epoch() == 0 {
        let unit = record
            .epoch_zero()
            .ok_or_else(|| anyhow::anyhow!("creator lost its original unit"))?;
        anyhow::ensure!(
            info == unit.group_info_bytes() && tree == unit.ratchet_tree_bytes(),
            "ready creator private state differs from its original recovery unit"
        );
    }
    Ok(())
}

/// A stopped loser stays stopped. Only separately acquired private state
/// matching the accepted winner/current public tree can admit this endpoint.
pub(crate) fn validate_superseded_private_group(
    record: &arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord,
    group: &arkret_sdk::ArkretMlsGroup,
    current: &arkret_wire::MlsGroupCurrent,
) -> anyhow::Result<()> {
    let winner = record
        .superseded_winner()
        .ok_or_else(|| anyhow::anyhow!("creator has no terminal winner"))?;
    let (_, tree) = group.public_group_state_bytes()?;
    let reference = format!(
        "ak:blob:{}",
        arkret_sdk::canonical::digest(
            arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                &current.public_tree_ref
            )?
            .digest_suite()?,
            &tree
        )
    );
    anyhow::ensure!(
        winner.accepted().event.event_id == current.genesis_event_ref
            && group.scope() == record.intent().effective_scope()
            && group.scope() == &current.effective_scope
            && group.group_id() == winner.immutable_genesis_binding().mls_group_id()?
            && group.epoch() == current.epoch
            && group.local_actor_id() == record.intent().owner_actor_id()
            && current.public_tree_ref.as_str() == reference,
        "losing private state cannot match the accepted Genesis winner; use Welcome, migration or recovery"
    );
    Ok(())
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

/// Read SDK payload bindings from an intent or its immutable authored Event.
/// Keeping the envelope intact prevents pairing a kind with another payload.
pub(crate) trait ApplicationEvent: arkret_sdk::EventMetadataSendGateExt {
    fn kind(&self) -> &arkret_sdk::EventKind;
    fn typed_payload<K: arkret_sdk::EventSpec>(&self) -> anyhow::Result<K::Payload>;
}

impl ApplicationEvent for arkret_sdk::EventIntent {
    fn kind(&self) -> &arkret_sdk::EventKind {
        self.kind()
    }

    fn typed_payload<K: arkret_sdk::EventSpec>(&self) -> anyhow::Result<K::Payload> {
        let payload = self.typed_payload::<K>()?;
        K::validate_payload(&payload)?;
        Ok(payload)
    }
}

impl ApplicationEvent for arkret_sdk::Event {
    fn kind(&self) -> &arkret_sdk::EventKind {
        &self.kind
    }

    fn typed_payload<K: arkret_sdk::EventSpec>(&self) -> anyhow::Result<K::Payload> {
        Ok(arkret_sdk::EventPayloadExt::typed_payload::<K>(self)?)
    }
}

impl ApplicationBody {
    /// The gated body of one SDK Event or intent, or `None` when its kind
    /// carries no application content the send gate governs.
    pub(crate) fn of_event(event: &impl ApplicationEvent) -> anyhow::Result<Option<Self>> {
        use arkret_sdk::event_spec;
        match event.kind() {
            arkret_sdk::EventKind::SpaceCreate
            | arkret_sdk::EventKind::StrandCreate
            | arkret_sdk::EventKind::SpaceUpdate
            | arkret_sdk::EventKind::StrandUpdate => {
                let metadata = event.event_metadata_send_gate()?.ok_or_else(|| {
                    anyhow::anyhow!("metadata Event has no SDK send-gate projection")
                })?;
                anyhow::ensure!(
                    !metadata.user_metadata_present || metadata.encrypted_metadata.is_empty(),
                    "metadata write mixes plaintext and ciphertext"
                );
                Ok(if !metadata.encrypted_metadata.is_empty() {
                    Some(Self::Encrypted(metadata.encrypted_metadata))
                } else if metadata.user_metadata_present {
                    Some(Self::Plaintext)
                } else {
                    None
                })
            }
            arkret_sdk::EventKind::MessageCreate => {
                let payload = event.typed_payload::<event_spec::MessageCreate>()?;
                payload.to_value()?;
                Self::of_message(payload.encrypted_content, payload.encrypted_metadata).map(Some)
            }
            arkret_sdk::EventKind::MessageRevise => {
                let payload = event.typed_payload::<event_spec::MessageRevise>()?;
                Self::of_message(payload.encrypted_content, payload.encrypted_metadata).map(Some)
            }
            arkret_sdk::EventKind::ReactionAdd => {
                let payload = event.typed_payload::<event_spec::ReactionAdd>()?;
                Ok(payload
                    .encrypted_payload
                    .map(|envelope| Self::Encrypted(vec![envelope])))
            }
            _ => Ok(None),
        }
    }

    fn of_message(
        content: Option<arkret_sdk::EncryptedEnvelope>,
        metadata: Option<arkret_sdk::EncryptedEnvelope>,
    ) -> anyhow::Result<Self> {
        Ok(match (content, metadata) {
            (Some(content), metadata) => {
                Self::Encrypted(std::iter::once(content).chain(metadata).collect())
            }
            (None, None) => Self::Plaintext,
            (None, Some(_)) => anyhow::bail!("encrypted_metadata requires encrypted_content"),
        })
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
    let current = read_durable_mls_current(input, scope).await;
    if matches!(current, Ok(None)) && matches!(body, ApplicationBody::Plaintext) {
        check_local_creator_plaintext_fence(input, scope).await?;
    }
    check_application_body_against(current, input.local.as_ref(), body)
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
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
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

    const STRAND: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
    const SPACE: &str = "ak:space:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    fn actor() -> arkret_sdk::ActorId {
        crate::test_support::account_actor("ak:did_core:web:alice.example")
    }

    fn draft() -> arkret_sdk::TypedEventDraft<arkret_sdk::event_spec::MessageCreate> {
        arkret_sdk::TypedEventDraft::new(
            scope(),
            actor(),
            arkret_sdk::MessageCreatePayload::with_content(
                arkret_sdk::StrandId::new(STRAND).unwrap(),
                "discussion",
                arkret_sdk::ContentBlock::text("message"),
            ),
        )
        .unwrap()
    }

    // The persisted intent boundary can receive malformed JSON; authored
    // Events can likewise be recovered from storage. Exercise both actual
    // SDK readers, without replacing the production payload dispatch.
    fn assert_payload_body(
        kind: arkret_sdk::EventKind,
        payload: serde_json::Value,
        expected: Option<ApplicationBody>,
    ) {
        let mut intent =
            serde_json::to_value(draft().into_intent(crate::clock::now_utc()).unwrap()).unwrap();
        intent["kind"] = serde_json::to_value(&kind).unwrap();
        intent["payload"] = payload.clone();
        let intent: arkret_sdk::EventIntent = serde_json::from_value(intent).unwrap();
        let mut authored = draft()
            .author_with_digest_suite(crate::clock::now_utc(), arkret_sdk::DigestSuite::Sha256)
            .unwrap()
            .event()
            .clone();
        authored.kind = kind;
        authored.payload = payload.as_object().unwrap().clone().into_iter().collect();
        assert_eq!(ApplicationBody::of_event(&intent).unwrap(), expected);
        assert_eq!(ApplicationBody::of_event(&authored).unwrap(), expected);
    }

    fn assert_payload_rejected(kind: arkret_sdk::EventKind, payload: serde_json::Value) {
        let mut intent =
            serde_json::to_value(draft().into_intent(crate::clock::now_utc()).unwrap()).unwrap();
        intent["kind"] = serde_json::to_value(&kind).unwrap();
        intent["payload"] = payload.clone();
        let intent: arkret_sdk::EventIntent = serde_json::from_value(intent).unwrap();
        let mut authored = draft()
            .author_with_digest_suite(crate::clock::now_utc(), arkret_sdk::DigestSuite::Sha256)
            .unwrap()
            .event()
            .clone();
        authored.kind = kind;
        authored.payload = payload.as_object().unwrap().clone().into_iter().collect();
        assert!(ApplicationBody::of_event(&intent).is_err());
        assert!(ApplicationBody::of_event(&authored).is_err());
    }

    fn encrypted(kind: &str) -> arkret_sdk::EncryptedEnvelope {
        let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
            actor(),
            crate::test_support::device_id("ak:device:01904100-0000-7000-8000-000000000001"),
        )
        .unwrap();
        let mut group = identity.create_group(&scope()).unwrap();
        let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            "application/json",
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            scope(),
            kind,
            group.epoch(),
            event(2),
            group.local_content_sender_domain().unwrap(),
            if kind == arkret_sdk::EventKind::ReactionAdd.as_str() {
                arkret_sdk::EventContentRoutingContext::Reaction {
                    target_ref: event(3),
                    routing_window: 0,
                    routing_tag: arkret_sdk::base64url_encode([7u8; 32]),
                }
            } else {
                arkret_sdk::EventContentRoutingContext::None
            },
        )
        .unwrap();
        let payload = group.encrypt_payload(header, b"{}").unwrap();
        arkret_sdk::mls::encrypted_envelope_from_payload(&payload).unwrap()
    }

    #[test]
    fn only_message_content_and_encrypted_reactions_are_gated() {
        use arkret_sdk::EventKind;
        use serde_json::json;
        assert_payload_body(
            EventKind::MessageCreate,
            json!({
                "strand_id": STRAND, "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "message"}
            }),
            Some(ApplicationBody::Plaintext),
        );
        assert_payload_body(
            EventKind::MessageRevise,
            json!({
                "message_id": arkret_sdk::MessageId::from_event_id(&event(3)),
                "content": {"kind": "ak.content.text", "body": "revised"}
            }),
            Some(ApplicationBody::Plaintext),
        );
        assert_payload_body(
            EventKind::ReactionAdd,
            json!({
                "target_ref": arkret_sdk::MessageId::from_event_id(&event(3)), "key": "+1"
            }),
            None,
        );
        assert_payload_body(EventKind::MemberState, json!({}), None);
        assert_payload_rejected(EventKind::MessageCreate, json!({"encrypted_metadata": {}}));
    }

    #[test]
    fn typed_payload_readers_reject_wrong_kind_and_malformed_message_carriers() {
        use arkret_sdk::EventKind;
        use serde_json::json;
        let message = json!({"strand_id": STRAND, "track_name": "discussion", "content": {
            "kind": "ak.content.text", "body": "message"
        }});
        assert_payload_rejected(EventKind::MessageRevise, message.clone());
        assert_payload_rejected(EventKind::ReactionAdd, message.clone());
        assert_payload_rejected(EventKind::SpaceCreate, message.clone());
        assert_payload_rejected(EventKind::StrandCreate, message.clone());
        let mut absent = message.clone();
        absent.as_object_mut().unwrap().remove("content");
        assert_payload_rejected(EventKind::MessageCreate, absent);
        let mut both = message.clone();
        both["encrypted_content"] =
            serde_json::to_value(encrypted(EventKind::MessageCreate.as_str())).unwrap();
        assert_payload_rejected(EventKind::MessageCreate, both);
        let mut unknown = message;
        unknown["retired_field"] = json!(true);
        assert_payload_rejected(EventKind::MessageCreate, unknown);
    }

    #[test]
    fn encrypted_message_revise_and_reaction_preserve_all_epoch_references() {
        use arkret_sdk::EventKind;
        use serde_json::json;
        for kind in [EventKind::MessageCreate, EventKind::MessageRevise] {
            let envelope = encrypted(kind.as_str());
            let mut payload =
                json!({"encrypted_content": envelope, "encrypted_metadata": envelope});
            if kind == EventKind::MessageCreate {
                payload["strand_id"] = json!(STRAND);
                payload["track_name"] = json!("discussion");
            } else {
                payload["message_id"] = json!(arkret_sdk::MessageId::from_event_id(&event(3)));
            }
            let body = ApplicationBody::Encrypted(vec![envelope.clone(), envelope]);
            assert_payload_body(kind, payload, Some(body.clone()));
            assert_eq!(
                check_application_body_against(Ok(Some(current(0, 1, 1))), None, body.clone()),
                Ok(())
            );
            assert_eq!(
                check_application_body_against(Ok(Some(current(1, 1, 1))), None, body),
                Err(MlsSendGateBlocked::EpochMismatch)
            );
        }
        let envelope = encrypted(EventKind::ReactionAdd.as_str());
        assert_payload_body(
            EventKind::ReactionAdd,
            json!({
                "target_ref": arkret_sdk::MessageId::from_event_id(&event(3)), "key": "+1", "encrypted_payload": envelope
            }),
            Some(ApplicationBody::Encrypted(vec![envelope])),
        );
    }

    #[test]
    fn metadata_create_and_patch_use_sdk_objects_and_whole_envelopes() {
        use arkret_sdk::EventKind;
        use serde_json::json;
        let space = arkret_sdk::Space::create_object(
            arkret_sdk::RealmId::new(REALM).unwrap(),
            "list",
            "title",
            actor(),
        );
        let strand = arkret_sdk::Strand::new_create(
            arkret_sdk::RealmId::new(REALM).unwrap(),
            "title",
            actor(),
        );
        assert_payload_body(
            EventKind::SpaceCreate,
            json!({"object": space}),
            Some(ApplicationBody::Plaintext),
        );
        assert_payload_body(
            EventKind::StrandCreate,
            json!({"object": strand}),
            Some(ApplicationBody::Plaintext),
        );
        for (key, value) in [
            ("title", json!(null)),
            ("summary", json!(null)),
            ("labels", json!([])),
            ("avatar_blob_ref", json!(null)),
        ] {
            let mut private_space = space.clone();
            private_space.title = None;
            private_space.encrypted_metadata = Some(encrypted(EventKind::SpaceCreate.as_str()));
            let mut payload = json!({"object": private_space});
            payload["object"][key] = value;
            assert_payload_rejected(EventKind::SpaceCreate, payload);
        }
        let mut null_metadata = json!({"object": strand});
        null_metadata["object"]["metadata"] = json!(null);
        null_metadata["object"]["encrypted_metadata"] =
            json!(encrypted(EventKind::StrandCreate.as_str()));
        assert_payload_rejected(EventKind::StrandCreate, null_metadata);
        let mut private = strand.clone();
        private.metadata = None;
        let envelope = encrypted(EventKind::StrandCreate.as_str());
        private.encrypted_metadata = Some(envelope.clone());
        assert_payload_body(
            EventKind::StrandCreate,
            json!({"object": private}),
            Some(ApplicationBody::Encrypted(vec![envelope])),
        );
        for kind in [EventKind::SpaceUpdate, EventKind::StrandUpdate] {
            let target = if kind == EventKind::SpaceUpdate {
                "space_id"
            } else {
                "target_ref"
            };
            let id = if kind == EventKind::SpaceUpdate {
                SPACE
            } else {
                STRAND
            };
            let envelope = encrypted(kind.as_str());
            let mut payload =
                json!({"patch": {"encrypted_metadata": {"$op": "set", "value": envelope}}});
            payload[target] = json!(id);
            assert_payload_body(
                kind.clone(),
                payload,
                Some(ApplicationBody::Encrypted(vec![envelope])),
            );
            let plain_path = if kind == EventKind::SpaceUpdate {
                "title"
            } else {
                "metadata.title"
            };
            let mut plain = json!({"patch": {}});
            plain["patch"][plain_path] = json!({"$op": "set", "value": "new"});
            plain[target] = json!(id);
            assert_payload_body(kind.clone(), plain, Some(ApplicationBody::Plaintext));
            let structural_patch = if kind == EventKind::SpaceUpdate {
                json!({"rank": "U"})
            } else {
                json!({"schema_refs": []})
            };
            let mut structural = json!({"patch": structural_patch});
            structural[target] = json!(id);
            assert_payload_body(kind, structural, None);
        }
    }

    #[test]
    fn metadata_patches_reject_malformed_mixed_and_partial_envelopes() {
        use arkret_sdk::EventKind;
        use serde_json::json;
        for kind in [EventKind::SpaceUpdate, EventKind::StrandUpdate] {
            let target = if kind == EventKind::SpaceUpdate {
                "space_id"
            } else {
                "target_ref"
            };
            let id = if kind == EventKind::SpaceUpdate {
                SPACE
            } else {
                STRAND
            };
            let envelope = encrypted(kind.as_str());
            let plain_path = if kind == EventKind::SpaceUpdate {
                "title"
            } else {
                "metadata.title"
            };
            let mut mixed = json!({"encrypted_metadata": {"$op": "set", "value": envelope}});
            mixed[plain_path] = json!("plaintext");
            for patch in [
                json!(null),
                json!([]),
                json!({}),
                json!({"encrypted_metadata": {"$op": "unset"}}),
                json!({"encrypted_metadata": envelope}),
                json!({"encrypted_metadata": {"$op": "set", "value": {}}}),
                json!({"encrypted_metadata.ciphertext": {"$op": "set", "value": "AA"}}),
                mixed,
            ] {
                let mut payload = json!({"patch": patch});
                payload[target] = json!(id);
                assert_payload_rejected(kind.clone(), payload);
            }
            let mut missing = json!({});
            missing[target] = json!(id);
            assert_payload_rejected(kind, missing);
        }
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
