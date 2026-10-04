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
    let _install = welcome_install_lock().lock().await;
    let transition = accepted_mls_transition(item)?;
    if item.event.kind == arkret_sdk::EventKind::MlsGenesis {
        let vault = crate::outbound_store::InksonOutboundStore::open(
            authority,
            crate::outbound_store::OutboundLane::Standard,
        )
        .map_err(|error| error.to_string())?;
        vault
            .check_creator_artifact_candidate(&item.event)
            .await
            .map_err(|error| error.to_string())?;
    }
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
            let group = crate::mls::persistence::restore_envelope(&staged, &snapshot_secret, 0)
                .map_err(describe)?;
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                serde_json::from_value(serde_json::Value::Object(
                    item.event.payload.clone().into_iter().collect(),
                ))
                .map_err(|error| error.to_string())?;
            let (info, tree) = group.public_group_state_bytes().map_err(describe)?;
            if payload.group_info_ref.as_str()
                != format!(
                    "ak:blob:{}",
                    arkret_sdk::canonical::digest(
                        arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(&payload.group_info_ref).map_err(describe)?.digest_suite().map_err(describe)?,
                        &info
                    )
                )
                || payload.ratchet_tree_ref.as_str()
                    != format!(
                        "ak:blob:{}",
                        arkret_sdk::canonical::digest(
                            arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(&payload.ratchet_tree_ref).map_err(describe)?.digest_suite().map_err(describe)?,
                            &tree
                        )
                    )
            {
                return Err(
                    "accepted Genesis public material differs from local private state".into(),
                );
            }
            group
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

fn welcome_install_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Complete a sender's exact accepted queue item after a runtime restart.
/// The staged provider checkpoint and its accepted base survive independently
/// of the moving Station current. Historical roster evidence restores leaf
/// attribution only after the exact own pending RFC Commit has been merged.
pub(crate) async fn install_recovered_outbound_commit(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    item: &CommittedEventFullView,
) -> Result<MlsInstallOutcome, String> {
    let _install = welcome_install_lock().lock().await;
    let transition = accepted_mls_transition(item)?;
    let base = state
        .read(|store| {
            store.mls_checkpoint_for_scope_and_group(
                &transition.effective_scope,
                transition.mls_group_id.as_str(),
            )
        })
        .ok_or_else(|| "recovered MLS Commit has no staged checkpoint".to_owned())?;
    if base.epoch >= transition.next_epoch && base.group_state_event_id.is_some() {
        return Ok(MlsInstallOutcome::AlreadyCurrent);
    }
    if base.epoch != transition.previous_epoch {
        return Ok(MlsInstallOutcome::BaseEpochMissing);
    }
    let base_ref = base
        .group_state_event_id
        .as_ref()
        .ok_or_else(|| "recovered MLS Commit has no accepted base Event".to_owned())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = super::load_device_checkpoint_secret(secure_store.as_ref(), authority, device_id)
        .map_err(describe)?;
    let mut group =
        crate::mls::persistence::restore_envelope(&base, &secret, base.epoch).map_err(describe)?;
    group
        .install_recovered_own_commit(item, base_ref)
        .map_err(describe)?;
    crate::mls::roster_install::install_welcome_roster_from_service(
        api, state, &mut group, item, authority,
    )
    .await?;
    persist_installed_group(
        state,
        &transition,
        &group,
        &secret,
        item.event.event_id.clone(),
    )
    .await
}

/// Join this device's endpoint into a group from one accepted Welcome delivery.
///
/// The SDK verifies the delivery against the accepted Commit it names, so this
/// supplies the KeyPackage private identity state of the exact claim `claim`
/// names -- already read from this device's own Station and verified
/// ([`verified_welcome_claim`]). Historical leaf authority is independently
/// fetched and verified against the accepted current before persistence.
pub(crate) async fn install_accepted_welcome(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    delivery: &arkret_wire::MlsWelcomeDelivery,
    accepted_commit: &CommittedEventFullView,
    claim: &VerifiedWelcomeClaim,
) -> Result<MlsInstallOutcome, String> {
    let transition = accepted_mls_transition(accepted_commit)?;
    // Bootstrap and stream convergence can observe the same delivery while
    // the first installer awaits roster evidence or its durable flush. Hold
    // this asynchronous lock through persistence, then recheck the checkpoint
    // below so only one installer signs the immutable consume command and no
    // later installer replaces an already advanced receive ratchet.
    let _welcome_install = welcome_install_lock().lock().await;
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
        &claim.record.keypackage_ref,
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

    crate::mls::roster_install::install_welcome_roster_from_service(
        api,
        state,
        &mut group,
        accepted_commit,
        authority,
    )
    .await?;
    // device-lifecycle.md §9: the consume this endpoint owes is signed now
    // and becomes durable with the joined group; it is sent only after both
    // are durable.
    let consume = crate::mls::welcome_consume::sign_welcome_consume(
        delivery,
        &claim.outcome,
        authority,
        device_id,
        &claim.station,
        transition.next_epoch,
    )?;
    persist_joined_welcome(
        state,
        &transition,
        &group,
        &snapshot_secret,
        transition.event().event_id.clone(),
        &consume,
    )
    .await
}

/// The claim a Welcome names, as read from and verified against this
/// endpoint's own Station.
pub(crate) struct VerifiedWelcomeClaim {
    pub(crate) record: arkret_sdk::KeyPackageClaimRecord,
    pub(crate) outcome: arkret_sdk::KeyPackagesClaimOutcome,
    pub(crate) station: arkret_sdk::DidCoreId,
}

/// Send every consume command this device durably owes, exactly as signed,
/// and forget the ones its Station settled (device-lifecycle.md §9). A lost
/// response keeps the command owed for the next pass.
pub(crate) async fn deliver_owed_keypackage_consumes(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
) {
    // Pending intents become visible in memory before their durable barrier
    // resolves. Another convergence pass must not send one during installation.
    let _welcome_install = welcome_install_lock().lock().await;
    let owed = state.read(|store| store.pending_keypackage_consumes());
    if owed.is_empty() {
        return;
    }
    let clients = crate::transport::EndpointClients::new(api.clone());
    let attempts = crate::mls::welcome_consume::drain_owed_consumes(owed, |(_, request)| {
        let clients = clients.clone();
        async move {
            crate::mls::welcome_consume::classify_consume_response(
                &clients.mls().consume_key_package(&request).await,
            )
        }
    })
    .await;
    for ((claim_id, _), attempt) in attempts {
        match &attempt {
            crate::mls::welcome_consume::ConsumeAttempt::Consumed => {}
            crate::mls::welcome_consume::ConsumeAttempt::Retry(error) => {
                tracing::debug!(%claim_id, %error, "KeyPackage consume stays owed");
                continue;
            }
            crate::mls::welcome_consume::ConsumeAttempt::Refused(error) => {
                tracing::warn!(%claim_id, %error, "KeyPackage consume was refused");
            }
        }
        match state.write(|store| store.forget_pending_keypackage_consume(&claim_id)) {
            Ok(barrier) => {
                if let Err(error) = barrier.wait().await {
                    tracing::warn!(%claim_id, %error, "settled KeyPackage consume not forgotten");
                }
            }
            Err(error) => {
                tracing::warn!(%claim_id, %error, "settled KeyPackage consume not forgotten");
            }
        }
    }
}

/// Whether this endpoint retains a Welcome that still needs installation.
pub(crate) fn has_pending_mls_welcome_for_endpoint(
    store: &crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> bool {
    crate::mls::welcome_delivery::pending_welcome_deliveries(&store.to_device_inbox())
        .iter()
        .any(|delivery| {
            let endpoint = garth::LocalMlsEndpoint::device(
                delivery.realm_id.clone(),
                arkret_sdk::ActorId::account(authority.clone()),
                device_id.clone(),
            );
            garth::mls::welcome_matches_endpoint(delivery, &endpoint)
                && store
                    .mls_checkpoint_for_scope(&delivery.effective_scope)
                    .is_none()
        })
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
    deliver_owed_keypackage_consumes(api, state).await;
    let deliveries = state.read(|store| {
        crate::mls::welcome_delivery::pending_welcome_deliveries(&store.to_device_inbox())
    });
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
        // device-lifecycle.md §9.2.4: the claim is read from this device's
        // own Station and verified before the Welcome is decrypted; a read or
        // binding failure leaves the Welcome undecrypted in the inbox.
        let claim =
            match verified_welcome_claim(api, &delivery, &endpoint, &accepted_commit, device_id)
                .await
            {
                Ok(claim) => claim,
                Err(error) => {
                    tracing::warn!(
                        welcome = %delivery.welcome_id.as_str(),
                        %error,
                        "MLS Welcome claim is not verified; the Welcome stays undecrypted",
                    );
                    continue;
                }
            };
        match install_accepted_welcome(
            api,
            state,
            authority,
            device_id,
            &delivery,
            &accepted_commit,
            &claim,
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
    if applied > 0 {
        deliver_owed_keypackage_consumes(api, state).await;
    }
    let scopes = state.read(|store| store.mls_scopes_needing_tail_recovery());
    for scope in scopes {
        applied += recover_remote_tail(api, state, authority, device_id, &scope).await?;
    }
    Ok(applied)
}

async fn recover_remote_tail(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
) -> Result<usize, String> {
    let rows = crate::realm_events_engine::verified_mls_recovery_tail(api, scope)
        .await
        .map_err(describe)?;
    let _install = welcome_install_lock().lock().await;
    let current = state
        .read(|store| store.current_mls_group_for_scope(scope))
        .ok_or_else(|| "MLS recovery has no verified current".to_owned())?;
    let group_id = scope.canonical_mls_group_id().map_err(describe)?;
    let base = state
        .read(|store| store.mls_checkpoint_for_scope_and_group(scope, group_id.as_str()))
        .ok_or_else(|| "MLS recovery has no local checkpoint".to_owned())?;
    if base.epoch >= current.epoch {
        return Ok(0);
    }
    let mut base_ref = base
        .group_state_event_id
        .clone()
        .ok_or_else(|| "MLS recovery has no accepted local base".to_owned())?;
    let base_position = rows
        .iter()
        .position(|row| row.event.event_id == base_ref)
        .ok_or_else(|| "authorized MLS tail does not disclose the installed base".to_owned())?;
    let base_transition = accepted_mls_transition(&rows[base_position])?;
    if base_transition.effective_scope != *scope
        || base_transition.next_epoch != base.epoch
        || base_transition.mls_group_id != group_id
    {
        return Err("verified MLS base differs from the local checkpoint".to_owned());
    }
    let target_position = rows
        .iter()
        .position(|row| row.event.event_id == current.current_mls_commit_event_ref)
        .ok_or_else(|| "authorized MLS tail does not reach verified current".to_owned())?;
    if target_position <= base_position {
        return Err("MLS recovery current precedes its base".to_owned());
    }
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = super::load_device_checkpoint_secret(secure.as_ref(), authority, device_id)
        .map_err(describe)?;
    let mut group =
        crate::mls::persistence::restore_envelope(&base, &secret, base.epoch).map_err(describe)?;
    if group.scope() != scope
        || group.identity().actor_id != arkret_sdk::ActorId::account(authority.clone())
        || group.identity().endpoint
            != (arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id: authority.principal_id.clone(),
                device_id: device_id.clone(),
            })
    {
        return Err("MLS recovery checkpoint belongs to another endpoint".to_owned());
    }
    let mut applied = 0;
    for item in &rows[base_position + 1..=target_position] {
        if item.event.kind != arkret_sdk::EventKind::MlsCommit {
            continue;
        }
        let transition = accepted_mls_transition(item)?;
        if transition.effective_scope != *scope || transition.previous_epoch != group.epoch() {
            return Err("MLS recovery tail is not a continuous epoch lineage".to_owned());
        }
        group
            .install_recovered_remote_commit(item, &base_ref)
            .map_err(describe)?;
        crate::mls::roster_install::install_welcome_roster_from_service(
            api, state, &mut group, item, authority,
        )
        .await?;
        persist_installed_group(
            state,
            &transition,
            &group,
            &secret,
            item.event.event_id.clone(),
        )
        .await?;
        base_ref = item.event.event_id.clone();
        applied += 1;
    }
    if group.epoch() != current.epoch || base_ref != current.current_mls_commit_event_ref {
        return Err("MLS recovery tail did not materialize verified current".to_owned());
    }
    Ok(applied)
}

/// The claim record a Welcome names, read through
/// `ak.self.keys.keypackages.read.claim.v1` from this device's own Station
/// with its receipt verified, and bound to the delivery, this endpoint's
/// current device authorization and the accepted Commit's inline Add.
async fn verified_welcome_claim(
    api: &crate::transport::TransportClient,
    delivery: &arkret_wire::MlsWelcomeDelivery,
    endpoint: &garth::LocalMlsEndpoint,
    accepted_commit: &CommittedEventFullView,
    device_id: &arkret_sdk::DeviceId,
) -> Result<VerifiedWelcomeClaim, String> {
    let clients = crate::transport::EndpointClients::new(api.clone());
    let (outcome, station) = clients
        .mls()
        .own_key_package_claim(&delivery.keypackage_claim_ref)
        .await
        .map_err(|error| format!("read the Welcome's KeyPackage claim: {error}"))?;
    let authorization = crate::mls::admission::current_requester_device_authorize_event_id(
        api.http(),
        device_id.as_str(),
    )
    .await?;
    let record = garth::mls::verify_welcome_claim(
        delivery,
        endpoint,
        &accepted_commit.event,
        &outcome,
        &station,
        &authorization,
    )
    .map_err(describe)?;
    Ok(VerifiedWelcomeClaim {
        record,
        outcome,
        station,
    })
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
    let envelope = sealed_checkpoint(transition, group, snapshot_secret)?;
    let scope = transition.effective_scope.clone();
    let barrier = state.write(|store| {
        store.install_accepted_mls_transition(&scope, envelope, &accepted_event_id)
    })?;
    let published = barrier.wait().await.map_err(describe);
    state.write(|_| {});
    published?;
    Ok(MlsInstallOutcome::Applied)
}

/// Persist the group a Welcome joined together with the consume command it
/// owes, in one durable flush. A flush that does not resolve drops the
/// command, so a join that is not durable is never consumed.
async fn persist_joined_welcome(
    state: &StateStoreHandle,
    transition: &AcceptedMlsTransition,
    group: &arkret_sdk::ArkretMlsGroup,
    snapshot_secret: &str,
    accepted_event_id: arkret_sdk::EventId,
    consume: &arkret_sdk::KeyPackagesConsumeRequestBody,
) -> Result<MlsInstallOutcome, String> {
    let envelope = sealed_checkpoint(transition, group, snapshot_secret)?;
    record_joined_welcome(
        state,
        &transition.effective_scope,
        envelope,
        &accepted_event_id,
        consume,
    )
    .await?;
    Ok(MlsInstallOutcome::Applied)
}

/// Install a joined Welcome's checkpoint and its owed consume in one flush;
/// when the flush does not resolve, the consume is dropped again so it is
/// never sent for a join that is not durable.
async fn record_joined_welcome(
    state: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
    envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    accepted_event_id: &arkret_sdk::EventId,
    consume: &arkret_sdk::KeyPackagesConsumeRequestBody,
) -> Result<(), String> {
    let barrier = state.write(|store| {
        store.install_accepted_mls_welcome(scope, envelope, accepted_event_id, consume)
    })?;
    let published = barrier.wait().await;
    state.write(|_| {});
    if let Err(error) = published {
        let claim_id = consume.claim_id.as_str().to_owned();
        let _ = state.write(|store| store.forget_pending_keypackage_consume(&claim_id));
        return Err(describe(error));
    }
    Ok(())
}

/// The device-secret-encrypted checkpoint of `group` at the accepted
/// transition's exact coordinate.
fn sealed_checkpoint(
    transition: &AcceptedMlsTransition,
    group: &arkret_sdk::ArkretMlsGroup,
    snapshot_secret: &str,
) -> Result<crate::mls::persistence::MlsLocalCheckpointEnvelope, String> {
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
    Ok(crate::mls::persistence::encrypt_state(
        realm_id.as_str(),
        post_state.group_id.as_str(),
        post_state.epoch,
        &encoded,
        snapshot_secret,
        &salt,
    ))
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

    fn consume_command() -> arkret_sdk::KeyPackagesConsumeRequestBody {
        let method = arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap();
        let signature = || arkret_sdk::KeyOperationSignature {
            kid: arkret_sdk::NonEmptyString::new(method.as_str().to_owned()).unwrap(),
            signature_algorithm: Some(arkret_sdk::NonEmptyString::new("Ed25519").unwrap()),
            sig: arkret_sdk::Base64UrlString::new("A".repeat(86)).unwrap(),
        };
        let delivery = welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id(),
        });
        arkret_sdk::KeyPackagesConsumeRequestBody {
            claim_id: delivery.keypackage_claim_ref.clone(),
            recipient_durable_receipt: arkret_sdk::RecipientMlsDurableReceipt {
                domain: arkret_sdk::NonEmptyString::new(
                    arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
                )
                .unwrap(),
                claim_request_id: arkret_sdk::Base64UrlString::new("Y2xhaW0tcmVxdWVzdA").unwrap(),
                key_package_ref: arkret_sdk::NonEmptyString::new(format!(
                    "sha256:{}",
                    "33".repeat(32)
                ))
                .unwrap(),
                recipient: arkret_sdk::RecipientMlsDurableSigner::Device {
                    recipient_account_id: authority(),
                    recipient_device_id: device_id(),
                    device_verification_method: method.clone(),
                },
                recipient_id: authority().station_id,
                realm_id: realm_id(),
                mls_group_id: garth::mls::mls_group_id_for_realm(&realm_id()).unwrap(),
                mls_epoch: 1,
                welcome_ref: delivery.welcome_id.clone(),
                welcome_digest: delivery.durable_receipt_digest().unwrap(),
                durable_at: chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
                signature: signature(),
            },
            signature: signature(),
        }
    }

    fn checkpoint() -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
        crate::mls::persistence::encrypt_state(REALM, "AQID", 1, b"one", "test-secret", &[7; 16])
    }

    fn accepted_event() -> arkret_sdk::EventId {
        arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk").unwrap()
    }

    fn handle(
        store: crate::state::LocalStateStore,
    ) -> (
        StateStoreHandle,
        std::sync::Arc<std::sync::Mutex<crate::state::LocalStateStore>>,
    ) {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(store));
        let read = shared.clone();
        let write = shared.clone();
        (
            StateStoreHandle::new(
                move |callback| callback(&read.lock().unwrap()),
                move |callback| callback(&mut write.lock().unwrap()),
            ),
            shared,
        )
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "inkson-welcome-consume-{name}-{}-{}",
            std::process::id(),
            crate::operation::uuid_v7(),
        ))
    }

    fn owed_bytes(store: &crate::state::LocalStateStore) -> Vec<String> {
        store
            .pending_keypackage_consumes()
            .into_iter()
            .map(|(_, request)| arkret_sdk::canonical::canonical_json_string(&request).unwrap())
            .collect()
    }

    /// decision 0121: a joined Welcome whose checkpoint flush does not
    /// resolve owes no consume, so nothing is ever sent for it.
    #[tokio::test]
    async fn a_join_that_is_not_durable_owes_no_consume() {
        let blocker = temp_path("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let (state, shared) = handle(crate::state::LocalStateStore::with_path(
            blocker.join("state.json"),
        ));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        assert!(
            record_joined_welcome(
                &state,
                &scope,
                checkpoint(),
                &accepted_event(),
                &consume_command()
            )
            .await
            .is_err()
        );
        assert!(owed_bytes(&shared.lock().unwrap()).is_empty());
        let _ = std::fs::remove_file(blocker);
    }

    /// A durable join owes its consume across a restart; a lost response
    /// resends the exact same signed bytes, and a settled consume is
    /// forgotten durably.
    #[tokio::test]
    async fn a_lost_consume_response_resends_the_durable_command_unchanged() {
        let path = temp_path("durable").with_extension("json");
        let (state, _) = handle(crate::state::LocalStateStore::with_path(&path));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let command = consume_command();
        record_joined_welcome(&state, &scope, checkpoint(), &accepted_event(), &command)
            .await
            .unwrap();
        let signed = arkret_sdk::canonical::canonical_json_string(&command).unwrap();
        let restarted = crate::state::LocalStateStore::with_path(&path);
        assert_eq!(owed_bytes(&restarted), vec![signed.clone()]);

        let sent = std::cell::RefCell::new(Vec::new());
        let lost = crate::mls::welcome_consume::drain_owed_consumes(
            restarted.pending_keypackage_consumes(),
            |(_, request)| {
                sent.borrow_mut()
                    .push(arkret_sdk::canonical::canonical_json_string(&request).unwrap());
                async { crate::mls::welcome_consume::ConsumeAttempt::Retry("lost".to_owned()) }
            },
        )
        .await;
        assert!(lost.iter().all(|(_, attempt)| !attempt.settled()));
        let (state, shared) = handle(restarted);
        let consumed = crate::mls::welcome_consume::drain_owed_consumes(
            shared.lock().unwrap().pending_keypackage_consumes(),
            |(_, request)| {
                sent.borrow_mut()
                    .push(arkret_sdk::canonical::canonical_json_string(&request).unwrap());
                async { crate::mls::welcome_consume::ConsumeAttempt::Consumed }
            },
        )
        .await;
        assert_eq!(sent.into_inner(), vec![signed.clone(), signed]);
        for ((claim_id, _), attempt) in consumed {
            assert!(attempt.settled());
            state
                .write(|store| store.forget_pending_keypackage_consume(&claim_id))
                .unwrap()
                .wait()
                .await
                .unwrap();
        }
        assert!(owed_bytes(&crate::state::LocalStateStore::with_path(&path)).is_empty());
        let _ = std::fs::remove_file(path);
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
            cipher_suite: arkret_wire::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
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
