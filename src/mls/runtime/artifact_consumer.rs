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

/// Install this device's accepted `ak.mls.genesis` or staged `ak.mls.commit`.
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
            let mut group =
                crate::mls::persistence::restore_envelope(&base, &snapshot_secret, base.epoch)
                    .map_err(describe)?;
            // The durable own pending Commit pins its historical GroupContext.
            // A moving current may already describe the accepted next epoch or
            // await stream catch-up; neither is the original authoring base.
            install_staged_outbound_commit(
                &mut group,
                item,
                base_event_id,
                authority,
                device_id,
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
    accepted_source: &AcceptedWelcomeCommit,
    claim: &VerifiedWelcomeClaim,
) -> Result<MlsInstallOutcome, String> {
    let accepted_commit = accepted_source.full()?;
    let transition = accepted_mls_transition(accepted_commit)?;
    // Bootstrap and stream convergence can observe the same delivery while
    // the first installer awaits roster evidence or its durable flush. Hold
    // this asynchronous lock through persistence, then recheck the checkpoint
    // below so only one installer signs the immutable consume command and no
    // later installer replaces an already advanced receive ratchet.
    let _welcome_install = welcome_install_lock().lock().await;
    state.read(|store| accepted_source.check_install(store, authority))?;
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
        accepted_source,
        authority,
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
        let claim = match verified_welcome_claim(
            api,
            &delivery,
            &endpoint,
            accepted_commit.full()?,
            device_id,
        )
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

// Preserve the existing 200-row network page size and finite captured head.
// Only relevant original artifact carriers consume this additional memory cap.
const MAX_RECOVERY_MATERIAL_BYTES: usize = 8 * 1024 * 1024;

type RecoverySnapshot = arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
    arkret_sdk::RealmId,
    arkret_wire::RealmStateSnapshot,
>;
type RecoveryAnchor = arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
    arkret_wire::StreamScanRequest,
    arkret_wire::StreamScanOutcome,
>;

/// Original private HTTP carriers remain live until the last durable install.
/// The local base is a candidate identity, never an authorization predecessor.
struct OwnRecoveryTail {
    client: arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    snapshot: RecoverySnapshot,
    anchor: RecoveryAnchor,
    pages: Vec<garth::own_station_results::OwnStationScanPage>,
    current: arkret_wire::MlsGroupCurrent,
    replica: garth::own_station_results::OwnStationReplica,
    expected_head: arkret_wire::CommitStreamHead,
}

impl OwnRecoveryTail {
    fn check_session(&self) -> Result<(), String> {
        self.snapshot.value().map_err(describe)?;
        if self.replica.head(&self.expected_head.stream_ref) != Some(&self.expected_head) {
            return Err("MLS recovery prefix has not reached its exact current head".into());
        }
        self.anchor.value().map_err(describe)?;
        for page in &self.pages {
            page.rows().map_err(describe)?;
        }
        self.client.check_session().map_err(describe)
    }

    fn full_rows(&self) -> Result<Vec<CommittedEventFullView>, String> {
        self.check_session()?;
        let mut rows = self
            .anchor
            .value()
            .map_err(describe)?
            .committed_events
            .clone();
        for page in &self.pages {
            rows.extend_from_slice(page.rows().map_err(describe)?);
        }
        let target = rows
            .iter()
            .position(|row| row.commit().event_ref == self.current.current_mls_commit_event_ref)
            .ok_or("authorized MLS tail does not reach its exact current Event")?;
        rows.truncate(target + 1);
        rows.into_iter()
            .map(|row| match row {
                CommittedEventView::Full(full) => Ok(full),
                CommittedEventView::Withheld(_) => {
                    Err("MLS recovery lineage contains a withheld original".to_owned())
                }
            })
            .collect()
    }

    fn check_install(
        &self,
        store: &crate::state::LocalStateStore,
        authority: &arkret_sdk::AccountId,
        scope: &arkret_sdk::ScopeRef,
        expected_base: &arkret_sdk::EventId,
        expected_epoch: u64,
        expected_checkpoint: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    ) -> Result<(), String> {
        self.check_session()?;
        if self.client.session().map_err(describe)?.account_id() != authority
            || store.active_authority().as_ref() != Some(authority)
            || store.current_reset_required()
            || store.current_mls_group_for_scope(scope).as_ref() != Some(&self.current)
        {
            return Err("MLS recovery account or exact current changed before installation".into());
        }
        let base = store
            .mls_checkpoint_for_scope_and_group(
                scope,
                scope.canonical_mls_group_id().map_err(describe)?.as_str(),
            )
            .ok_or("MLS recovery local base disappeared")?;
        require_unchanged_recovery_base(&base, expected_checkpoint, expected_base, expected_epoch)
    }
}

// Network proof acquisition pins the accepted lineage coordinate, not a private
// receive ratchet. Freeze the latest executable state only after that proof is
// available; every subsequent installation still uses the full checkpoint CAS.
pub(super) fn refreeze_recovery_base(
    actual: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    requested: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
) -> Result<crate::mls::persistence::MlsLocalCheckpointEnvelope, String> {
    if actual.realm_id != requested.realm_id
        || actual.group_id != requested.group_id
        || actual.epoch != requested.epoch
        || actual.admission_epoch != requested.admission_epoch
        || actual.group_state_event_id != requested.group_state_event_id
        || actual.group_state_event_id.is_none()
        || actual.aead_version != requested.aead_version
    {
        return Err("MLS recovery accepted local base changed during proof acquisition".into());
    }
    Ok(actual.clone())
}

pub(super) fn require_unchanged_recovery_base(
    actual: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    expected: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
    reference: &arkret_sdk::EventId,
    epoch: u64,
) -> Result<(), String> {
    if actual.epoch != epoch
        || actual.group_state_event_id.as_ref() != Some(reference)
        || actual != expected
    {
        return Err(
            "MLS recovery local base or private ratchet changed before installation".into(),
        );
    }
    Ok(())
}

async fn own_recovery_tail(
    client: arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    scope: &arkret_sdk::ScopeRef,
    base_ref: &arkret_sdk::EventId,
) -> Result<OwnRecoveryTail, String> {
    let realm = scope
        .realm_id_opt()
        .ok_or("MLS recovery scope has no Realm")?;
    let stream = arkret_wire::CommitStreamRef::from_scope(scope, None).map_err(describe)?;
    let snapshot = client.snapshot_head(realm).await.map_err(describe)?;
    let mut replica = garth::own_station_results::OwnStationReplica::new(realm.clone());
    replica
        .install_bound_snapshot(&snapshot)
        .map_err(describe)?;
    let cut = snapshot.value().map_err(describe)?;
    let head = cut
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or("MLS recovery current omits its independent stream")?
        .clone();
    let floor = cut
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|floor| floor.stream_ref == stream)
        .ok_or("MLS recovery current omits its history floor")?
        .oldest_position;
    let mut currents = cut
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } if scope_ref == scope => Some(value),
            _ => None,
        });
    let current: arkret_wire::MlsGroupCurrent = serde_json::from_value(
        currents
            .next()
            .ok_or("MLS recovery current omits the scope MLS result")?
            .clone(),
    )
    .map_err(describe)?;
    if currents.next().is_some() || current.effective_scope != *scope {
        return Err("MLS recovery current has duplicate or mismatched scope".into());
    }
    // GET supplies only the candidate coordinates. An actual exact scan must
    // re-admit the original and its historical producer before it is a base.
    let candidate = client
        .committed_event_get(base_ref)
        .await
        .map_err(describe)?;
    let CommittedEventView::Full(base) = candidate.value().map_err(describe)? else {
        return Err("MLS recovery installed base is withheld".into());
    };
    if base.event.event_id != *base_ref
        || base.event.scope_ref != *scope
        || base.commit.stream_ref != stream
        || base.commit.stream_position < floor
        || base.commit.stream_position > head.stream_position
        || base.commit.governance_generation > cut.governance_generation
    {
        return Err("MLS recovery base is outside its exact scope/current floor".into());
    }
    let reference = arkret_wire::CommittedEventRef {
        event_id: base_ref.clone(),
        commit_id: base.commit.commit_id.clone(),
        stream_ref: stream.clone(),
        stream_position: base.commit.stream_position,
    };
    let anchor = client
        .scan_commit_stream(&arkret_wire::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::Before(Some(
                reference
                    .stream_position
                    .checked_add(1)
                    .ok_or("MLS recovery base position overflow")?,
            )),
            limit: 1,
        })
        .await
        .map_err(describe)?;
    if anchor
        .value()
        .map_err(describe)?
        .committed_events
        .as_slice()
        != [CommittedEventView::Full(base.clone())]
        || anchor
            .value()
            .map_err(describe)?
            .readable_floor
            .as_ref()
            .map(|floor| floor.oldest_position)
            != Some(floor)
    {
        return Err("MLS recovery base scan changed its original or current floor".into());
    }
    let base_head = arkret_wire::CommitStreamHead {
        stream_ref: stream.clone(),
        stream_position: reference.stream_position,
        commit_id: reference.commit_id,
    };
    replica
        .restore_bound_head(&client, &base_head, anchor.clone())
        .await
        .map_err(describe)?;
    candidate.value().map_err(describe)?;
    let mut after = base_head.stream_position;
    let mut pages = Vec::new();
    let mut retained_bytes = serde_json::to_vec(anchor.value().map_err(describe)?)
        .map_err(describe)?
        .len();
    if retained_bytes > MAX_RECOVERY_MATERIAL_BYTES {
        return Err("MLS recovery base exceeds bounded in-memory capacity".into());
    }
    let mut target_seen = *base_ref == current.current_mls_commit_event_ref;
    while after < head.stream_position {
        let remaining = head.stream_position - after;
        let response = client
            .scan_commit_stream(&arkret_wire::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(Some(after)),
                limit: remaining.min(200) as u16,
            })
            .await
            .map_err(describe)?;
        let page = replica
            .apply_bound_scan(&client, response)
            .await
            .map_err(describe)?;
        if page.rows().map_err(describe)?.is_empty() {
            return Err("MLS recovery stream ends before its exact current head".into());
        }
        after = replica
            .head(&stream)
            .ok_or("MLS recovery scan has no continuous head")?
            .stream_position;
        let relevant = page.rows().map_err(describe)?.iter().any(|row| match row {
            CommittedEventView::Full(full) => {
                full.event.event_id == current.current_mls_commit_event_ref
                    || matches!(
                        full.event.kind,
                        arkret_sdk::EventKind::MlsGenesis | arkret_sdk::EventKind::MlsCommit
                    )
            }
            CommittedEventView::Withheld(_) => !target_seen,
        });
        target_seen |= page
            .rows()
            .map_err(describe)?
            .iter()
            .any(|row| row.commit().event_ref == current.current_mls_commit_event_ref);
        if relevant {
            retained_bytes = retained_bytes
                .checked_add(
                    serde_json::to_vec(page.rows().map_err(describe)?)
                        .map_err(describe)?
                        .len(),
                )
                .ok_or("MLS recovery proof size overflow")?;
            if retained_bytes > MAX_RECOVERY_MATERIAL_BYTES {
                return Err("MLS recovery artifacts exceed bounded in-memory capacity".into());
            }
            pages.push(page);
        }
        // Unrelated ordinary pages have already advanced the closed replica;
        // releasing them places no limit on the total historical span.
    }
    if replica.head(&stream) != Some(&head) {
        return Err("MLS recovery scan forks its exact current head".into());
    }
    let tail = OwnRecoveryTail {
        client,
        snapshot,
        anchor,
        pages,
        current,
        replica,
        expected_head: head,
    };
    tail.check_session()?;
    Ok(tail)
}

pub(crate) async fn recover_remote_tail(
    api: &crate::transport::TransportClient,
    state: &StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
) -> Result<usize, String> {
    let group_id = scope.canonical_mls_group_id().map_err(describe)?;
    let requested_base = state
        .read(|store| store.mls_checkpoint_for_scope_and_group(scope, group_id.as_str()))
        .ok_or("MLS recovery has no local checkpoint")?;
    let requested_base_ref = requested_base
        .group_state_event_id
        .as_ref()
        .ok_or("MLS recovery has no accepted local base")?;
    let tail = own_recovery_tail(
        crate::transport::own_station_results::client_for_http(api.http())
            .await
            .map_err(describe)?,
        scope,
        requested_base_ref,
    )
    .await?;
    let rows = tail.full_rows()?;
    let _install = welcome_install_lock().lock().await;
    tail.check_session()?;
    let current = tail.current.clone();
    let base = state.read(|store| {
        let actual = store
            .mls_checkpoint_for_scope_and_group(scope, group_id.as_str())
            .ok_or("MLS recovery local base disappeared")?;
        let frozen = refreeze_recovery_base(&actual, &requested_base)?;
        tail.check_install(
            store,
            authority,
            scope,
            requested_base_ref,
            requested_base.epoch,
            &frozen,
        )?;
        Ok::<_, String>(frozen)
    })?;
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
    group
        .verify_installed_historical_base(&rows[base_position], &base_ref)
        .map_err(describe)?;
    let mut expected_checkpoint = base.clone();
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
        let envelope = sealed_checkpoint(&transition, &group, &secret)?;
        let (barrier, written_checkpoint) = state.write(|store| {
            tail.check_install(
                store,
                authority,
                scope,
                &base_ref,
                transition.previous_epoch,
                &expected_checkpoint,
            )?;
            let barrier =
                store.install_accepted_mls_transition(scope, envelope, &item.event.event_id)?;
            // Capture exactly this write while still holding the same state
            // critical section, never a later receive/send write-back.
            let written = store
                .mls_checkpoint_for_scope_and_group(scope, group_id.as_str())
                .ok_or("MLS recovery installation did not store its checkpoint")?;
            Ok::<_, String>((barrier, written))
        })?;
        let published = barrier.wait().await.map_err(describe);
        state.write(|_| {});
        published?;
        tail.check_session()?;
        base_ref = item.event.event_id.clone();
        expected_checkpoint = written_checkpoint;
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
pub(crate) struct AcceptedWelcomeCommit {
    client: arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    response: RecoveryAnchor,
}

impl AcceptedWelcomeCommit {
    fn full(&self) -> Result<&CommittedEventFullView, String> {
        self.client.check_session().map_err(describe)?;
        let [CommittedEventView::Full(full)] = self
            .response
            .value()
            .map_err(describe)?
            .committed_events
            .as_slice()
        else {
            return Err("Welcome accepted original is withheld or ambiguous".into());
        };
        Ok(full)
    }

    fn check_install(
        &self,
        store: &crate::state::LocalStateStore,
        authority: &arkret_sdk::AccountId,
    ) -> Result<(), String> {
        self.full()?;
        if self.client.session().map_err(describe)?.account_id() != authority
            || store.active_authority().as_ref() != Some(authority)
            || store.current_reset_required()
        {
            return Err("Welcome account/session changed before installation".into());
        }
        Ok(())
    }
}

async fn accepted_commit_for_welcome(
    api: &crate::transport::TransportClient,
    delivery: &arkret_wire::MlsWelcomeDelivery,
) -> Result<Option<AcceptedWelcomeCommit>, String> {
    let client = crate::transport::own_station_results::client_for_http(api.http())
        .await
        .map_err(describe)?;
    accepted_welcome_original(client, delivery).await
}

async fn accepted_welcome_original(
    client: arkret_sdk::http_client::own_station_results::OwnStationResultClient,
    delivery: &arkret_wire::MlsWelcomeDelivery,
) -> Result<Option<AcceptedWelcomeCommit>, String> {
    let stream_ref = arkret_wire::CommitStreamRef::from_scope(&delivery.effective_scope, None)
        .map_err(describe)?;
    let mut after_position = None;
    loop {
        let response = client
            .scan_commit_stream(&arkret_wire::StreamScanRequest {
                realm_id: delivery.realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction: arkret_wire::StreamScanDirection::After(after_position),
                limit: WELCOME_COMMIT_SCAN_PAGE,
            })
            .await
            .map_err(describe)?;
        let page = response.value().map_err(describe)?;
        if let Some(item) = page.committed_events.iter().find_map(|item| match item {
            CommittedEventView::Full(full) if full.event.event_id == delivery.commit_event_ref => {
                Some(full)
            }
            _ => None,
        }) {
            if item.event.kind != arkret_sdk::EventKind::MlsCommit
                || item.event.scope_ref != delivery.effective_scope
            {
                return Err("Welcome accepted Commit has another kind/scope".into());
            }
            let reference = arkret_wire::CommittedEventRef {
                event_id: item.event.event_id.clone(),
                commit_id: item.commit.commit_id.clone(),
                stream_ref: item.commit.stream_ref.clone(),
                stream_position: item.commit.stream_position,
            };
            let exact = client
                .scan_commit_stream(&arkret_wire::StreamScanRequest {
                    realm_id: delivery.realm_id.clone(),
                    stream_ref: stream_ref.clone(),
                    direction: arkret_wire::StreamScanDirection::Before(Some(
                        reference
                            .stream_position
                            .checked_add(1)
                            .ok_or("Welcome Commit position overflow")?,
                    )),
                    limit: 1,
                })
                .await
                .map_err(describe)?;
            let exact =
                garth::own_station_results::consume_bound_scan_row(&client, &reference, exact)
                    .await
                    .map_err(describe)?;
            if exact.value().map_err(describe)?.committed_events.as_slice()
                != [CommittedEventView::Full(item.clone())]
            {
                return Err("Welcome Commit exact read changed its original".into());
            }
            response.value().map_err(describe)?;
            client.check_session().map_err(describe)?;
            return Ok(Some(AcceptedWelcomeCommit {
                client,
                response: exact,
            }));
        }
        match page.committed_events.last() {
            Some(row) if page.truncated => after_position = Some(row.commit().stream_position),
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
    accepted_source: &AcceptedWelcomeCommit,
    authority: &arkret_sdk::AccountId,
) -> Result<MlsInstallOutcome, String> {
    let envelope = sealed_checkpoint(transition, group, snapshot_secret)?;
    record_joined_welcome_guarded(
        state,
        &transition.effective_scope,
        envelope,
        &accepted_event_id,
        consume,
        |store| accepted_source.check_install(store, authority),
    )
    .await?;
    accepted_source.full()?;
    Ok(MlsInstallOutcome::Applied)
}

/// Install a joined Welcome's checkpoint and its owed consume in one flush;
/// when the flush does not resolve, the consume is dropped again so it is
/// never sent for a join that is not durable.
#[cfg(test)]
async fn record_joined_welcome(
    state: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
    envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    accepted_event_id: &arkret_sdk::EventId,
    consume: &arkret_sdk::KeyPackagesConsumeRequestBody,
) -> Result<(), String> {
    record_joined_welcome_guarded(state, scope, envelope, accepted_event_id, consume, |_| {
        Ok(())
    })
    .await
}

async fn record_joined_welcome_guarded(
    state: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
    envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    accepted_event_id: &arkret_sdk::EventId,
    consume: &arkret_sdk::KeyPackagesConsumeRequestBody,
    guard: impl FnOnce(&crate::state::LocalStateStore) -> Result<(), String>,
) -> Result<(), String> {
    let barrier = state.write(|store| {
        guard(store)?;
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

fn install_staged_outbound_commit(
    group: &mut arkret_sdk::ArkretMlsGroup,
    item: &CommittedEventFullView,
    base_event_id: &arkret_sdk::EventId,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    authority_hints: &[MlsLeafAuthorityHint],
) -> Result<(), String> {
    let actor = arkret_sdk::ActorId::account(authority.clone());
    if group.identity().actor_id != actor
        || item.event.actor_id != actor
        || group.identity().endpoint
            != arkret_sdk::MlsEndpointIdentity::human_device(
                authority.principal_id.clone(),
                device_id.clone(),
            )
    {
        return Err("staged outbound MLS Commit belongs to another endpoint".to_owned());
    }
    let previous = group.verified_leaf_bindings().map_err(describe)?;
    group
        .install_recovered_own_commit(item, base_event_id)
        .map_err(describe)?;
    crate::mls::governance_proof::install_post_transition_leaf_bindings(
        group,
        &previous,
        authority_hints,
    )
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
        let pending_consumes = shared.lock().unwrap().pending_keypackage_consumes();
        let consumed =
            crate::mls::welcome_consume::drain_owed_consumes(pending_consumes, |(_, request)| {
                sent.borrow_mut()
                    .push(arkret_sdk::canonical::canonical_json_string(&request).unwrap());
                async { crate::mls::welcome_consume::ConsumeAttempt::Consumed }
            })
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
    fn staged_sidecar_commit_installs_from_immutable_base_after_restart() {
        let account = authority();
        let device = device_id();
        let actor = arkret_sdk::ActorId::account(account.clone());
        let create = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [51; 32]);
        let sidecar = arkret_sdk::SidecarId::from_event_id(&create);
        let scope = arkret_sdk::ScopeRef::Sidecar {
            realm_id: realm_id(),
            sidecar_id: sidecar.clone(),
        };
        let identity =
            arkret_sdk::ArkretMlsIdentity::new_test_human_device(actor.clone(), device.clone())
                .unwrap();
        let mut group = identity.create_group(&scope).unwrap();
        group
            .install_local_creator_binding(actor.clone(), Some(create.clone()))
            .unwrap();
        let base = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [52; 32]);
        let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            realm_id(),
            sidecar.clone(),
            Some(base.clone()),
            0,
            1,
            0,
            arkret_sdk::sidecar_participant_authority_digest(&sidecar, &realm_id(), &account, &[])
                .unwrap(),
            vec![create],
        )
        .unwrap();
        let before = group.export_state_record().unwrap();
        let envelope = group
            .self_update_commit_with_governance_binding(&binding)
            .unwrap();
        let accepted =
            crate::test_support::accepted_mls_commit_with_binding(actor, &envelope, binding, 53);
        let pending = serde_json::to_vec(&group.export_state_record().unwrap()).unwrap();
        let restore = || {
            arkret_sdk::ArkretMlsGroup::restore_from_state_record(
                &serde_json::from_slice(&pending).unwrap(),
            )
            .unwrap()
        };
        let mut restarted = restore();
        let wrong_base =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [54; 32]);
        assert!(
            install_staged_outbound_commit(
                &mut restarted,
                &accepted,
                &wrong_base,
                &account,
                &device,
                &[]
            )
            .is_err()
        );
        assert_eq!(restarted.epoch(), 0);
        let mut wrong_account = account.clone();
        wrong_account.station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:another.example").unwrap();
        assert!(
            install_staged_outbound_commit(
                &mut restarted,
                &accepted,
                &base,
                &wrong_account,
                &device,
                &[]
            )
            .is_err()
        );
        let wrong_device =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        assert!(
            install_staged_outbound_commit(
                &mut restarted,
                &accepted,
                &base,
                &account,
                &wrong_device,
                &[]
            )
            .is_err()
        );
        let mut unstaged = arkret_sdk::ArkretMlsGroup::restore_from_state_record(&before).unwrap();
        assert!(
            install_staged_outbound_commit(&mut unstaged, &accepted, &base, &account, &device, &[])
                .is_err()
        );
        install_staged_outbound_commit(&mut restarted, &accepted, &base, &account, &device, &[])
            .unwrap();
        assert_eq!(restarted.epoch(), 1);
        assert_eq!(restarted.verified_leaf_bindings().unwrap().len(), 1);
        assert!(
            install_staged_outbound_commit(
                &mut restarted,
                &accepted,
                &base,
                &account,
                &device,
                &[]
            )
            .is_err()
        );
    }
    struct RecoverySource(
        std::sync::Mutex<arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot>,
    );
    impl arkret_sdk::http_client::own_station_results::OwnStationSessionSource for RecoverySource {
        fn snapshot(
            &self,
        ) -> arkret_sdk::http_client::Result<
            arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot,
        > {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    // Closed transport fixture only: these bytes are never passed to RFC processing.
    fn recovery_commit_payload(
        base: arkret_sdk::EventId,
        previous_epoch: u64,
    ) -> serde_json::Value {
        let next_epoch = previous_epoch.checked_add(1).unwrap();
        let binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
            realm_id(),
            Some(base.clone()),
            previous_epoch,
            next_epoch,
            0,
        )
        .unwrap();
        let bytes = b"accepted-commit-source-fence-fixture";
        let envelope = arkret_sdk::MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: next_epoch,
            commit: arkret_sdk::base64url_encode(bytes),
            commit_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(bytes))
                .unwrap(),
            ratchet_tree: None,
        };
        let payload = arkret_sdk::MlsCommitPayload::new(base, 0, &envelope, binding).unwrap();
        payload.validate().unwrap();
        serde_json::to_value(payload).unwrap()
    }

    fn recovery_seal_commit(mut commit: arkret_sdk::RealmCommit) -> arkret_sdk::RealmCommit {
        let mut body = serde_json::to_value(&commit).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        commit.commit_id =
            arkret_sdk::RealmCommitId::from_digest(arkret_sdk::canonical::sha256_bytes(
                arkret_sdk::canonical::canonical_json_bytes(&body).unwrap(),
            ));
        let commit =
            crate::test_support::committed_event::FixtureStation::did_web().seal_commit(commit);
        commit.verify_commit_id_matches_content().unwrap();
        let wire: arkret_sdk::RealmCommit =
            serde_json::from_value(serde_json::to_value(&commit).unwrap()).unwrap();
        assert_eq!(
            wire, commit,
            "canonical millisecond wire roundtrip retains signed original"
        );
        wire.verify_commit_id_matches_content().unwrap();
        wire
    }

    /// Independently located original PCR authorization transport coordinates.
    /// This does not claim actual PG admission or independently download PCR
    /// permissions; the real historical query and Event Ed verifier remain active.
    fn recovery_original_source(
        event: &arkret_sdk::Event,
        template: &arkret_sdk::RealmCommit,
    ) -> (arkret_sdk::ResolvedSignerKey, chrono::DateTime<chrono::Utc>) {
        let create = arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::canonical::sha256_bytes(b"artifact recovery original PCR create"),
        );
        let source_event = arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::canonical::sha256_bytes(b"artifact recovery original Device authorization"),
        );
        let mut genesis = template.clone();
        genesis.realm_id = arkret_sdk::RealmId::from_event_id(&create);
        genesis.stream_ref = arkret_sdk::CommitStreamRef::Realm {
            realm_id: genesis.realm_id.clone(),
        };
        genesis.event_ref = create.clone();
        genesis.stream_position = 0;
        genesis.previous_commit_ref = None;
        genesis.producer_signer_fact_digest = None;
        genesis.authority_ref = arkret_sdk::RealmCommitAuthorityRef::GenesisOrChangeEvent(create);
        genesis.committed_at = crate::test_support::committed_event::fixture_time(50);
        let genesis = recovery_seal_commit(genesis);
        let mut source = genesis.clone();
        source.event_ref = source_event;
        source.stream_position = 1;
        source.previous_commit_ref = Some(genesis.commit_id);
        let source = recovery_seal_commit(source);
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            event
                .producer_proof
                .as_ref()
                .unwrap()
                .verification_method
                .clone(),
        );
        let key = arkret_sdk::ResolvedSignerKey {
            public_key_b64u: arkret_sdk::Base64UrlString::new(
                arkret_sdk::canonical::base64url_encode(signer.verifying_key().as_bytes()),
            )
            .unwrap(),
            authorization_ref: arkret_sdk::CommittedEventRef {
                event_id: source.event_ref,
                commit_id: source.commit_id.clone(),
                stream_ref: source.stream_ref,
                stream_position: source.stream_position,
            },
            revision: arkret_sdk::CurrentRevision {
                commit_id: source.commit_id,
                stream_position: source.stream_position,
            },
            governance_generation: source.governance_generation,
        };
        assert_ne!(key.authorization_ref.stream_ref, template.stream_ref);
        assert_ne!(key.authorization_ref.event_id, event.event_id);
        assert!(source.committed_at < template.committed_at);
        (key, source.committed_at)
    }

    fn recovery_signed_rows(
        entries: Vec<(String, serde_json::Value)>,
    ) -> Vec<CommittedEventFullView> {
        let (bundle, _, mut rows) = crate::test_support::committed_event::verified_realm_fixture_as(
            realm_id(),
            entries,
            "alice.example",
            "ak:device:0196419b-0000-7000-8000-000000000001",
        );
        let mut previous = recovery_seal_commit(bundle.genesis_commit).commit_id;
        for row in &mut rows {
            row.commit.previous_commit_ref = Some(previous);
            let (key, accepted_at) = recovery_original_source(&row.event, &row.commit);
            let human = row.event.human_device_producer().unwrap().unwrap();
            assert_eq!(human.account_id.station_id, authority().station_id);
            let fact = arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
                event_id: row.event.event_id.clone(),
                actor: row.event.actual_signer().clone(),
                device_id: human.device_id,
                verification_method: row
                    .event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .verification_method
                    .clone(),
                key,
                accepted_at,
            };
            fact.validate_event_binding(&row.event, arkret_sdk::DigestSuite::Sha256)
                .unwrap();
            row.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
            row.commit = recovery_seal_commit(row.commit.clone());
            fact.validate_commit_binding(row, arkret_sdk::DigestSuite::Sha256)
                .unwrap();
            previous = row.commit.commit_id.clone();
        }
        rows
    }

    fn recovery_fixture(
        fork: bool,
        withheld: bool,
        floor: u64,
    ) -> (Vec<serde_json::Value>, Vec<CommittedEventFullView>) {
        use serde_json::json;
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let initial_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x32; 32]);
        let first_payload = recovery_commit_payload(initial_ref.clone(), 0);
        let first = recovery_signed_rows(vec![(
            arkret_sdk::EventKind::MlsCommit.as_str().into(),
            first_payload.clone(),
        )])
        .remove(0);
        let mut rows = recovery_signed_rows(vec![
            (
                arkret_sdk::EventKind::MlsCommit.as_str().into(),
                first_payload,
            ),
            (
                arkret_sdk::EventKind::MlsCommit.as_str().into(),
                recovery_commit_payload(first.event.event_id.clone(), 1),
            ),
        ]);
        assert_eq!(rows[0].event.event_id, first.event.event_id);
        if fork {
            rows[1].commit.previous_commit_ref = rows[0].commit.previous_commit_ref.clone();
            rows[1].commit = recovery_seal_commit(rows[1].commit.clone());
        }
        let current = arkret_wire::MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: initial_ref,
            cipher_suite: arkret_sdk::NonEmptyString::new(
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            )
            .unwrap(),
            current_mls_commit_event_ref: rows[1].event.event_id.clone(),
            epoch: 2,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_sdk::BlobRef::new(format!(
                "ak:blob:sha256:{}",
                "22".repeat(32)
            ))
            .unwrap(),
        };
        let stream = rows[0].commit.stream_ref.clone();
        let mut snapshot = arkret_wire::RealmStateSnapshot {
            snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
            realm_id: realm_id(),
            governance_generation: 0,
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: stream.clone(),
                    oldest_position: floor,
                }],
            },
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream.clone(),
                stream_position: 2,
                commit_id: rows[1].commit.commit_id.clone(),
            }],
            current_state_entries: vec![arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref: scope },
                source_stream_ref: stream,
                revision: arkret_wire::CurrentRevision {
                    commit_id: rows[1].commit.commit_id.clone(),
                    stream_position: 2,
                },
                value: serde_json::to_value(current).unwrap(),
            }],
            created_at: crate::test_support::committed_event::fixture_time(60),
            signature: rows[0].commit.signature.clone(),
        };
        crate::test_support::committed_event::sign_fixture_snapshot(&mut snapshot);
        let base = if withheld {
            json!({"commit":rows[0].commit,"event_disclosure":{"status":"withheld"}})
        } else {
            serde_json::to_value(&rows[0]).unwrap()
        };
        let mut bodies = vec![serde_json::to_value(snapshot).unwrap(), base];
        if !withheld && floor <= 1 {
            let readable = arkret_wire::ReadableFloor {
                oldest_position: floor,
                floor_commit_id: rows[0].commit.commit_id.clone(),
                floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
            };
            bodies.extend([
                json!({"committed_events":[rows[0]],"readable_floor":readable,"truncated":false}),
                json!({"__key":true}),
                json!({"committed_events":[rows[1]],"readable_floor":readable,"truncated":false}),
            ]);
            if !fork {
                bodies.push(json!({"__key":true}));
            }
        }
        (bodies, rows)
    }

    fn recovery_http(
        bodies: Vec<serde_json::Value>,
        original: &CommittedEventFullView,
    ) -> (
        arkret_sdk::http_client::own_station_results::OwnStationResultClient,
        std::sync::Arc<RecoverySource>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};

        use arkret_sdk::http_client::own_station_results::*;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let binding = arkret_sdk::StationConnectionBinding {
            service_id: authority().station_id.clone(),
            base_url: base.clone(),
            trust_domain: arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_sdk::AuthMetadata::minimal(),
        };
        let session = OwnStationSessionSnapshot::new(
            binding.clone(),
            authority(),
            authority().station_id,
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            0,
            "fixture-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let source = std::sync::Arc::new(RecoverySource(std::sync::Mutex::new(session)));
        let raw = arkret_sdk::http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_sdk::http_client::Auth::Bearer(
                "fixture-grant".into(),
            ))
            .build()
            .unwrap();
        let (original_key, original_accepted_at) =
            recovery_original_source(&original.event, &original.commit);
        let server = std::thread::spawn(move || {
            for body in bodies {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 8192];
                let start = loop {
                    let n = socket.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..start]).to_ascii_lowercase();
                assert!(headers.contains("authorization: bearer fixture-grant"));
                let len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < start + len {
                    let n = socket.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                }
                let body = if body.get("__key").is_some() {
                    let request: arkret_sdk::SignerKeysQueryRequestBody =
                        serde_json::from_slice(&bytes[start..start + len]).unwrap();
                    assert_eq!(request.queries.len(), 1);
                    assert!(request.queries[0].committed_event_ref().is_some());
                    serde_json::to_value(arkret_sdk::SignerKeysQueryOutcome {
                        request_id: request.request_id,
                        realm_id: request.realm_id,
                        recipient_account_id: request.recipient_account_id,
                        results: vec![arkret_sdk::SignerKeyQueryOutcome::HistoricalResolved {
                            selector: request.queries[0].clone(),
                            accepted_at: original_accepted_at,
                            key: original_key.clone(),
                        }],
                    })
                    .unwrap()
                } else {
                    body
                };
                let bytes = serde_json::to_vec(&body).unwrap();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",bytes.len()).unwrap();
                socket.write_all(&bytes).unwrap();
            }
        });
        (
            OwnStationResultClient::new(raw, binding, source.clone()).unwrap(),
            source,
            server,
        )
    }

    #[tokio::test]
    async fn ordinary_recovery_actual_http_prefix_preserves_carriers_and_session_fence() {
        use arkret_sdk::http_client::own_station_results::OwnStationSessionSource;
        let (bodies, rows) = recovery_fixture(false, false, 1);
        let (client, source, server) = recovery_http(bodies, &rows[0]);
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let tail = own_recovery_tail(client, &scope, &rows[0].event.event_id)
            .await
            .unwrap();
        assert_eq!(
            tail.full_rows().unwrap(),
            rows,
            "actual signed originals retain their admitted continuous prefix"
        );
        let old = source.snapshot().unwrap();
        *source.0.lock().unwrap() =
            arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot::new(
                old.binding().clone(),
                old.account_id().clone(),
                old.account_id().station_id.clone(),
                old.grant_id().clone(),
                old.epoch(),
                "fixture-grant".into(),
            )
            .unwrap()
            .with_provider_identity(Default::default());
        assert!(
            tail.check_session().is_err(),
            "same-grant/epoch provider replacement invalidates held responses"
        );
        assert!(tail.full_rows().is_err());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn ordinary_recovery_actual_http_fork_withheld_and_floor_loss_fail_closed() {
        for (fork, withheld, floor, reason) in [
            (true, false, 1, "fork"),
            (false, true, 1, "withheld"),
            (false, false, 2, "floor"),
        ] {
            let (bodies, rows) = recovery_fixture(fork, withheld, floor);
            let (client, _, server) = recovery_http(bodies, &rows[0]);
            let scope = arkret_sdk::ScopeRef::Realm {
                realm_id: realm_id(),
            };
            let error = match own_recovery_tail(client, &scope, &rows[0].event.event_id).await {
                Ok(_) => panic!("invalid recovery proof admitted"),
                Err(error) => error,
            };
            assert!(error.contains(reason), "{reason}: {error}");
            server.join().unwrap();
        }
    }
    #[tokio::test]
    async fn ordinary_welcome_actual_exact_scan_late_session_publishes_no_checkpoint_or_consume() {
        use arkret_sdk::http_client::own_station_results::OwnStationSessionSource;
        use serde_json::json;
        let item = recovery_signed_rows(vec![(
            arkret_sdk::EventKind::MlsCommit.as_str().into(),
            recovery_commit_payload(
                arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x32; 32]),
                0,
            ),
        )])
        .remove(0);
        let floor = arkret_wire::ReadableFloor {
            oldest_position: item.commit.stream_position,
            floor_commit_id: item.commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
        };
        let bodies = vec![
            json!({"committed_events":[item],"readable_floor":floor,"truncated":false}),
            json!({"committed_events":[item],"readable_floor":floor,"truncated":false}),
            json!({"__key":true}),
        ];
        let (client, source, server) = recovery_http(bodies, &item);
        let mut delivery = welcome_delivery(arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: device_id(),
        });
        delivery.commit_event_ref = item.event.event_id.clone();
        let accepted = accepted_welcome_original(client, &delivery)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.full().unwrap(),
            &item,
            "actual target scan was historically re-admitted"
        );
        let old = source.snapshot().unwrap();
        *source.0.lock().unwrap() =
            arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot::new(
                old.binding().clone(),
                old.account_id().clone(),
                old.account_id().station_id.clone(),
                old.grant_id().clone(),
                old.epoch(),
                "fixture-grant".into(),
            )
            .unwrap()
            .with_provider_identity(Default::default());
        let path = temp_path("ordinary-late-welcome");
        let (state, shared) = handle(crate::state::LocalStateStore::with_path(path.clone()));
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let error = record_joined_welcome_guarded(
            &state,
            &scope,
            checkpoint(),
            &item.event.event_id,
            &consume_command(),
            |store| accepted.check_install(store, &authority()),
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("session") || error.contains("changed"),
            "late actual carrier rejected: {error}"
        );
        assert!(
            shared
                .lock()
                .unwrap()
                .mls_checkpoint_for_scope(&scope)
                .is_none()
        );
        assert!(
            owed_bytes(&shared.lock().unwrap()).is_empty(),
            "no future consume obligation was created"
        );
        assert!(!path.exists(), "no durable write occurred");
        server.join().unwrap();
    }

    #[test]
    fn ordinary_recovery_same_epoch_private_ratchet_change_cannot_replace_captured_base() {
        let mut expected = checkpoint();
        expected.group_state_event_id = Some(accepted_event());
        assert!(
            require_unchanged_recovery_base(
                &expected,
                &expected,
                &accepted_event(),
                expected.epoch
            )
            .is_ok()
        );
        let mut received = expected.clone();
        received.ciphertext_hex.push_str("00");
        assert_eq!(received.epoch, expected.epoch);
        assert_eq!(received.group_state_event_id, expected.group_state_event_id);
        let error = require_unchanged_recovery_base(
            &received,
            &expected,
            &accepted_event(),
            expected.epoch,
        )
        .unwrap_err();
        assert!(error.contains("private ratchet"));
    }
    #[test]
    fn ordinary_recovery_refreeze_rejects_changed_accepted_coordinates() {
        let mut requested = checkpoint();
        requested.group_state_event_id = Some(accepted_event());
        for field in 0..5 {
            let mut changed = requested.clone();
            match field {
                0 => changed.epoch += 1,
                1 => changed.group_state_event_id = None,
                2 => changed.realm_id.push('x'),
                3 => changed.group_id.push('x'),
                _ => changed.admission_epoch += 1,
            }
            assert!(refreeze_recovery_base(&changed, &requested).is_err());
            assert_eq!(requested.group_state_event_id, Some(accepted_event()));
        }
    }

    #[test]
    fn ordinary_recovery_captures_latest_private_ratchet_after_authorized_read() {
        let mut requested = checkpoint();
        requested.group_state_event_id = Some(accepted_event());
        let mut received = requested.clone();
        received.ciphertext_hex.push_str("00");
        received.app_messages_observed += 1;
        let base = refreeze_recovery_base(&received, &requested).unwrap();
        assert_eq!(base, received);
        require_unchanged_recovery_base(&received, &base, &accepted_event(), base.epoch).unwrap();
        let mut later_receive = received.clone();
        later_receive.ciphertext_hex.push_str("11");
        assert!(
            require_unchanged_recovery_base(&later_receive, &base, &accepted_event(), base.epoch,)
                .is_err()
        );
        let mut advanced = received.clone();
        advanced.epoch += 1;
        assert!(refreeze_recovery_base(&advanced, &requested).is_err());
        let mut another_group = received.clone();
        another_group.group_id.push_str("other");
        assert!(refreeze_recovery_base(&another_group, &requested).is_err());
        let mut missing_base = requested.clone();
        missing_base.group_state_event_id = None;
        assert!(refreeze_recovery_base(&missing_base, &missing_base).is_err());
    }
}
