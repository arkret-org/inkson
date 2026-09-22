//! Install accepted MLS transitions into this device's provider state.
//!
//! An MLS transition is installable exactly when the governance Station has
//! committed its Event into the scope's own independent commit stream, so every
//! entry point here takes the accepted full committed-event view (or, for a Welcome, the
//! producer-signed delivery plus the accepted Commit it names). Nothing asks a
//! separate endpoint whether a transition was accepted, and nothing installs
//! provider state that is not bound to an exact commit coordinate.
//!
//! The install order per group is genesis, then each commit in epoch order. A
//! commit whose base epoch this device does not hold is left for a later pass
//! rather than applied out of order.

use arkret_wire::{CommittedEventFullView, CommittedEventView};

use crate::mls::accepted_artifact::{AcceptedMlsTransition, accepted_mls_transition};
use crate::mls::governance_proof::MlsLeafAuthorityHint;
use crate::runtime::input::StateStoreHandle;

/// What one install attempt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlsInstallOutcome {
    /// Provider state advanced and was persisted with its accepted Event.
    Applied,
    /// This device already holds an equal-or-newer epoch for the group.
    AlreadyCurrent,
    /// The transition's base epoch is not installed yet, so it stays pending.
    BaseEpochMissing,
}

fn describe(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Install one accepted `ak.mls.genesis` or `ak.mls.commit`.
///
/// `authority_hints` carry the checked KeyPackage claim evidence for every leaf
/// this transition newly occupies; a membership-changing commit without them
/// fails closed instead of attributing a leaf from credential bytes alone.
pub(crate) async fn install_accepted_transition(
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    item: &CommittedEventFullView,
    authority_hints: &[MlsLeafAuthorityHint],
) -> Result<MlsInstallOutcome, String> {
    let transition = accepted_mls_transition(item)?;
    if state.read(|store| {
        store.realm_projection_has_retired_minimal_metadata_marker(
            transition.effective_scope.realm_id().as_str(),
        )
    }) {
        return Err(
            "retired minimal-metadata Realm marker cannot install an MLS transition".to_owned(),
        );
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let snapshot_secret =
        super::load_device_checkpoint_secret(secure_store.as_ref(), authority, device_id)
            .map_err(describe)?;
    let installed = state.read(|store| {
        store.mls_checkpoint_for_scope_and_group(
            &transition.effective_scope,
            transition.mls_group_id.as_str(),
        )
    });
    if let Some(installed) = installed.as_ref()
        && installed.epoch >= transition.next_epoch
        && installed.group_state_event_id.is_some()
    {
        return Ok(MlsInstallOutcome::AlreadyCurrent);
    }

    let group = match &transition.event().kind {
        arkret_sdk::EventKind::MlsGenesis => {
            // Genesis carries no MLS message: the creator already holds the
            // epoch-zero group it published, and a non-creator only ever joins
            // a group through a Welcome delivery.
            let staged = installed.ok_or_else(|| {
                "accepted MLS Genesis has no epoch-zero authoring state on this device".to_owned()
            })?;
            if staged.epoch != 0 {
                return Err("accepted MLS Genesis authoring state is not epoch zero".to_owned());
            }
            crate::mls::persistence::restore_envelope(&staged, &snapshot_secret, 0)
                .map_err(describe)?
        }
        arkret_sdk::EventKind::MlsCommit => {
            let base = installed.ok_or_else(|| {
                "accepted MLS Commit has no installed base group on this device".to_owned()
            })?;
            if base.epoch != transition.previous_epoch {
                // The base epoch this Commit builds on is not installed yet, so
                // the transition stays pending rather than being applied out of
                // order.
                return Ok(MlsInstallOutcome::BaseEpochMissing);
            }
            let base_event_id = base.group_state_event_id.as_ref().ok_or_else(|| {
                "accepted MLS Commit base checkpoint has no accepted Event".to_owned()
            })?;
            let station_base = state
                .read(|store| store.current_mls_group_for_scope(&transition.effective_scope))
                .ok_or_else(|| {
                    "accepted MLS Commit has no pinned Station base current result".to_owned()
                })?;
            validate_station_base_current(
                &station_base,
                &transition.effective_scope,
                base_event_id,
                transition.previous_epoch,
            )?;
            let mut group =
                crate::mls::persistence::restore_envelope(&base, &snapshot_secret, base.epoch)
                    .map_err(describe)?;
            let previous = group.verified_leaf_bindings().map_err(describe)?;
            // This merges the committer's own staged commit as well as a remote
            // one: the staged pending commit travels inside the durable group
            // state, so an author that restarted between submission and
            // acceptance still installs exactly the epoch it authored.
            group
                .install_accepted_commit(item, &station_base)
                .map_err(describe)?;
            crate::mls::governance_proof::install_post_transition_leaf_bindings(
                &mut group,
                &previous,
                authority_hints,
            )?;
            group
        }
        other => {
            return Err(format!("MLS install received a {} Event", other.as_str()));
        }
    };
    persist_installed_group(
        state,
        &transition,
        &group,
        &snapshot_secret,
        transition.event().event_id.clone(),
    )
    .await
}

/// Join this device's endpoint into a group from one accepted Welcome delivery.
///
/// The SDK verifies the delivery against the accepted Commit it names, so this
/// only supplies the two host-held inputs: the KeyPackage private identity
/// state the claim consumed, and the verified leaf attribution for the joined
/// roster.
pub(crate) async fn install_accepted_welcome(
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    delivery: &arkret_wire::MlsWelcomeDelivery,
    accepted_commit: &CommittedEventFullView,
    authority_hints: &[MlsLeafAuthorityHint],
) -> Result<MlsInstallOutcome, String> {
    let transition = accepted_mls_transition(accepted_commit)?;
    if state.read(|store| {
        store.realm_projection_has_retired_minimal_metadata_marker(
            transition.effective_scope.realm_id().as_str(),
        )
    }) {
        return Err("retired minimal-metadata Realm marker cannot install a Welcome".to_owned());
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let snapshot_secret =
        super::load_device_checkpoint_secret(secure_store.as_ref(), authority, device_id)
            .map_err(describe)?;
    if let Some(installed) = state.read(|store| {
        store.mls_checkpoint_for_scope_and_group(
            &transition.effective_scope,
            transition.mls_group_id.as_str(),
        )
    }) && installed.epoch >= transition.next_epoch
    {
        // A replayed or late Welcome must never roll the local group back to
        // the join epoch.
        return Ok(MlsInstallOutcome::AlreadyCurrent);
    }

    let endpoint = welcome_endpoint_identity(delivery, authority, device_id)?;
    let private_state = super::load_mls_key_package_identity_state(
        secure_store.as_ref(),
        authority,
        device_id,
        delivery.keypackage_claim_ref.as_str(),
    )
    .map_err(describe)?
    .ok_or_else(|| "accepted Welcome KeyPackage private state is unavailable".to_owned())?;
    let identity = arkret_sdk::ArkretMlsIdentity::restore_from_private_state(
        delivery.recipient_actor_id.clone(),
        endpoint.clone(),
        &private_state,
    )
    .map_err(describe)?;
    if identity.endpoint_identity() != endpoint {
        return Err(
            "accepted MLS Welcome is not addressed to the locally persisted KeyPackage endpoint"
                .to_owned(),
        );
    }
    let mut group = arkret_sdk::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity,
        delivery,
        accepted_commit,
    )
    .map_err(describe)?;
    crate::mls::governance_proof::install_post_transition_leaf_bindings(
        &mut group,
        &[],
        authority_hints,
    )?;
    persist_installed_group(
        state,
        &transition,
        &group,
        &snapshot_secret,
        transition.event().event_id.clone(),
    )
    .await
}

/// Join every encrypted scope this device has been Welcomed into but has not
/// installed yet.
///
/// A Welcome is not an Event: it is a producer-signed `MlsWelcomeDelivery`
/// journalled into this device's durable to-device inbox, and the epoch it
/// joins at lives in the accepted `ak.mls.commit` it names. So one convergence
/// pass is exactly: read the journalled deliveries addressed to this endpoint,
/// resolve each one's accepted Commit on the scope's own independent stream,
/// and install it.
///
/// Scopes this device already holds a group for are skipped: later epochs
/// arrive as accepted transitions on that scope's stream
/// ([`install_accepted_transition`]), never by replaying the join Welcome.
///
/// One delivery that cannot be installed never fails the pass. It stays in the
/// inbox and is retried on the next pass, because a Welcome whose Commit has
/// not reached this Station replica yet, or whose roster needs Add-authority
/// evidence this device has not received, is pending rather than wrong. The
/// returned count is the number of scopes actually joined.
pub(crate) async fn converge_accepted_mls_artifacts(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<usize, String> {
    let deliveries = state.read(|store| {
        crate::mls::welcome_delivery::pending_welcome_deliveries(&store.to_device_inbox())
    });
    if deliveries.is_empty() {
        return Ok(0);
    }
    let actor_id = arkret_sdk::ActorId::account(authority.clone());
    let mut applied = 0;
    for delivery in deliveries {
        let endpoint = garth::LocalMlsEndpoint::device(
            delivery.realm_id.clone(),
            actor_id.clone(),
            device_id.clone(),
        );
        if !garth::mls::welcome_matches_endpoint(&delivery, &endpoint) {
            continue;
        }
        if state.read(|store| {
            store
                .mls_checkpoint_for_scope(&delivery.effective_scope)
                .is_some()
        }) {
            continue;
        }
        let accepted_commit = match accepted_commit_for_welcome(api, &delivery).await {
            Ok(Some(item)) => item,
            Ok(None) => {
                tracing::debug!(
                    welcome = %delivery.welcome_id.as_str(),
                    commit = %delivery.commit_event_ref.as_str(),
                    "accepted MLS Commit for a pending Welcome is not on the scope stream yet",
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    welcome = %delivery.welcome_id.as_str(),
                    %error,
                    "resolving the accepted Commit for a pending Welcome failed",
                );
                continue;
            }
        };
        match install_accepted_welcome(
            state,
            authority,
            device_id,
            &delivery,
            &accepted_commit,
            &[],
        )
        .await
        {
            Ok(MlsInstallOutcome::Applied) => applied += 1,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    welcome = %delivery.welcome_id.as_str(),
                    %error,
                    "accepted MLS Welcome is not installable yet",
                );
            }
        }
    }
    Ok(applied)
}

/// Resolve the exact accepted Commit a Welcome names on the scope's own stream.
///
/// The delivery carries only an `EventId`, and there is no Realm-global order
/// to look it up in, so the scan walks the one independent stream the Welcome's
/// `effective_scope` belongs to.
async fn accepted_commit_for_welcome(
    api: &crate::transport::TransportClient,
    delivery: &arkret_wire::MlsWelcomeDelivery,
) -> Result<Option<CommittedEventFullView>, String> {
    let stream_ref = arkret_wire::CommitStreamRef::from_scope(&delivery.effective_scope, None)
        .map_err(|error| format!("MLS Welcome scope has no commit stream: {error}"))?;
    let submitter = api
        .event_submitter()
        .map_err(|error| format!("MLS Welcome stream reader: {error}"))?;
    let mut after_position = None;
    loop {
        let page = submitter
            .scan_stream(&stream_ref, after_position, WELCOME_COMMIT_SCAN_PAGE)
            .await
            .map_err(|error| format!("scan the MLS Welcome commit stream: {error}"))?;
        if let Some(item) = page.0.committed_events.iter().find_map(|item| match item {
            CommittedEventView::Full(item) if item.event.event_id == delivery.commit_event_ref => {
                Some(item)
            }
            _ => None,
        }) {
            return Ok(Some(item.clone()));
        }
        match page.last_position() {
            Some(position) if page.truncated() => after_position = Some(position),
            _ => return Ok(None),
        }
    }
}

const WELCOME_COMMIT_SCAN_PAGE: u16 = 200;

/// The MLS endpoint identity a Welcome addressed to this device stands for.
fn welcome_endpoint_identity(
    delivery: &arkret_wire::MlsWelcomeDelivery,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> Result<arkret_sdk::MlsEndpointIdentity, String> {
    match &delivery.recipient_endpoint {
        arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient,
        } => {
            if recipient != device_id
                || delivery.recipient_actor_id != arkret_sdk::ActorId::account(authority.clone())
            {
                return Err("MLS Welcome delivery is addressed to another device".to_owned());
            }
            Ok(arkret_sdk::MlsEndpointIdentity::human_device(
                authority.principal_id.clone(),
                device_id.clone(),
            ))
        }
        // An Agent runtime Welcome is installed by that Agent's own runtime,
        // never by a human device acting on its behalf.
        arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime { .. } => {
            Err("an Agent runtime Welcome is not installable by a human device endpoint".to_owned())
        }
    }
}

/// Encrypt the post-transition provider state and publish it together with the
/// accepted Event that materialized it.
async fn persist_installed_group(
    state: &StateStoreHandle,
    transition: &AcceptedMlsTransition,
    group: &arkret_sdk::ArkretMlsGroup,
    snapshot_secret: &str,
    accepted_event_id: arkret_sdk::EventId,
) -> Result<MlsInstallOutcome, String> {
    let realm_id = transition
        .effective_scope
        .realm_id_opt()
        .ok_or_else(|| "accepted MLS transition has no Realm scope".to_owned())?
        .clone();
    let post_state = group.export_state_record().map_err(describe)?;
    validate_installed_coordinate(
        &post_state.group_id,
        post_state.epoch,
        &transition.mls_group_id,
        transition.next_epoch,
    )?;
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(describe)?;
    let encoded = serde_json::to_vec(&post_state).map_err(describe)?;
    let envelope = crate::mls::persistence::encrypt_state(
        realm_id.as_str(),
        post_state.group_id.as_str(),
        post_state.epoch,
        &encoded,
        snapshot_secret,
        &salt,
    );
    let scope = transition.effective_scope.clone();
    let barrier = state.write(|store| {
        store.install_accepted_mls_transition(&scope, envelope, &accepted_event_id)
    })?;
    barrier.wait().await.map_err(describe)?;
    Ok(MlsInstallOutcome::Applied)
}

fn validate_installed_coordinate(
    installed_group_id: &arkret_wire::MlsGroupId,
    installed_epoch: u64,
    accepted_group_id: &arkret_wire::MlsGroupId,
    accepted_epoch: u64,
) -> Result<(), String> {
    if installed_group_id != accepted_group_id || installed_epoch != accepted_epoch {
        return Err(
            "installed MLS state differs from the accepted transition group or epoch".to_owned(),
        );
    }
    Ok(())
}

fn validate_station_base_current(
    current: &arkret_wire::MlsGroupCurrent,
    effective_scope: &arkret_sdk::ScopeRef,
    base_event_id: &arkret_sdk::EventId,
    previous_epoch: u64,
) -> Result<(), String> {
    if &current.effective_scope != effective_scope
        || &current.current_mls_commit_event_ref != base_event_id
        || current.epoch != previous_epoch
    {
        return Err(
            "pinned Station MLS current result is not the exact transition base".to_owned(),
        );
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new(REALM.to_owned()).unwrap()
    }

    fn device_id() -> arkret_sdk::DeviceId {
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned())
            .unwrap()
    }

    fn authority() -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn welcome_delivery(
        recipient: arkret_wire::MlsWelcomeRecipientEndpoint,
    ) -> arkret_wire::MlsWelcomeDelivery {
        arkret_wire::MlsWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000009".to_owned(),
            )
            .unwrap(),
            realm_id: realm_id(),
            effective_scope: arkret_sdk::ScopeRef::Realm {
                realm_id: realm_id(),
            },
            commit_event_ref: arkret_sdk::EventId::new(
                "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
            )
            .unwrap(),
            recipient_actor_id: arkret_sdk::ActorId::account(authority()),
            recipient_endpoint: recipient,
            keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(
                "ak:keypackage_claim:01904100-0000-7000-8000-00000000000a".to_owned(),
            )
            .unwrap(),
            ciphertext_b64: arkret_sdk::Base64UrlString::new("AQID").unwrap(),
            producer_proof: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#key-1")
                    .unwrap(),
                signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32)))
                    .unwrap(),
                created_at: chrono::Utc::now(),
                sig: arkret_sdk::Base64UrlString::new("A".repeat(86)).unwrap(),
            },
        }
    }

    #[test]
    fn a_welcome_for_another_device_never_resolves_to_this_endpoint() {
        let other =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002".to_owned())
                .unwrap();
        let delivery =
            welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id: other });
        assert!(welcome_endpoint_identity(&delivery, &authority(), &device_id()).is_err());
    }

    #[test]
    fn an_agent_runtime_welcome_is_not_installable_by_a_human_device() {
        let delivery = welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: arkret_sdk::DidUrl::new("did:web:agent.example#key-1").unwrap(),
        });
        assert!(welcome_endpoint_identity(&delivery, &authority(), &device_id()).is_err());
    }

    #[test]
    fn a_welcome_with_the_right_principal_but_wrong_station_is_rejected() {
        let mut delivery = welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id(),
        });
        delivery.recipient_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            authority().principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap(),
        ));
        assert!(welcome_endpoint_identity(&delivery, &authority(), &device_id()).is_err());
    }

    #[test]
    fn this_devices_own_welcome_resolves_to_its_human_device_endpoint() {
        let delivery = welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id(),
        });
        assert_eq!(
            welcome_endpoint_identity(&delivery, &authority(), &device_id()).unwrap(),
            arkret_sdk::MlsEndpointIdentity::human_device(
                authority().principal_id.clone(),
                device_id()
            )
        );
    }

    #[test]
    fn installed_state_must_match_the_exact_accepted_group_and_epoch() {
        let accepted_group = arkret_wire::MlsGroupId::new("A".repeat(43)).unwrap();
        let another_group = arkret_wire::MlsGroupId::new("B".repeat(43)).unwrap();

        assert!(validate_installed_coordinate(&accepted_group, 7, &accepted_group, 7).is_ok());
        assert_eq!(
            validate_installed_coordinate(&another_group, 7, &accepted_group, 7).unwrap_err(),
            "installed MLS state differs from the accepted transition group or epoch"
        );
        assert_eq!(
            validate_installed_coordinate(&accepted_group, 6, &accepted_group, 7).unwrap_err(),
            "installed MLS state differs from the accepted transition group or epoch"
        );
    }

    #[test]
    fn station_current_must_be_the_exact_pre_transition_base() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let genesis = arkret_sdk::EventId::new(
            "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk".to_owned(),
        )
        .unwrap();
        let base = arkret_sdk::EventId::new(
            "ak:event:AbhX3-n_FG8scl_4zkFai8VRhqvIwjOeWHvA8D3mQ9V7".to_owned(),
        )
        .unwrap();
        let current = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis,
            current_mls_commit_event_ref: base.clone(),
            epoch: 7,
            current_key_access_revision: 11,
            covered_key_access_revision: 11,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "22".repeat(32)
            ))
            .unwrap(),
        };

        assert!(validate_station_base_current(&current, &scope, &base, 7).is_ok());

        let mut post_state = current.clone();
        post_state.epoch = 8;
        assert!(validate_station_base_current(&post_state, &scope, &base, 7).is_err());

        let another_event = arkret_sdk::EventId::new(
            "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq".to_owned(),
        )
        .unwrap();
        assert!(validate_station_base_current(&current, &scope, &another_event, 7).is_err());

        let another_scope = arkret_sdk::ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret_sdk::CircleId::new(
                "ak:circle:AcQajqaKFvyDoMpqpSlBvMh0d4gheZsVPhbHaTlqXtkV".to_owned(),
            )
            .unwrap(),
        };
        assert!(validate_station_base_current(&current, &another_scope, &base, 7).is_err());
    }
}
