//! MLS admission for Realm invites.
//!
//! Reconciles accepted invites into MLS group membership: which Realms still
//! owe an admission commit, the membership completeness hint the decision
//! rests on, and the genesis/governance frontier a commit needs before it can
//! be authored. Consumed by the MLS runtime effects as well as the members
//! panel, and unrelated to how any of it is rendered.

use super::*;

pub(super) async fn retain_current_history_secret_durable(
    mut state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<Option<(u64, zeroize::Zeroizing<Vec<u8>>)>> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.principal_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS history retention identity does not match the active account"
    );
    state_store
        .write()
        .reconcile_mls_group_state_ref_from_checkpoint(realm_id, None)
        .map_err(anyhow::Error::msg)?;
    let derived = {
        let store = state_store.read();
        crate::mls::runtime::derive_and_retain_realm_history_secret(
            &store,
            secure_store,
            realm_id,
            &account.authority,
            &account.device_id,
        )
    }
    .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    let Some((epoch, secret, pending)) = derived else {
        return Ok(None);
    };
    pending.persist(secure_store).await?;
    state_store.write().publish_history_secrets(pending);
    Ok(Some((epoch, secret)))
}

pub(super) fn mls_admission_authoring_lock(realm_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(realm_id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(realm_id.to_owned(), Arc::downgrade(&lock));
    lock
}

pub(crate) async fn submit_mls_admission_for_invitee(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    invitee_id: String,
    target_device_id_override: Option<String>,
) -> anyhow::Result<Option<u64>> {
    let authoring_lock = mls_admission_authoring_lock(&realm_id);
    let _authoring_guard = authoring_lock.lock().await;
    let invitee_actor: arkret_sdk::ActorId = serde_json::from_str(&invitee_id)?;
    let invitee_principal = invitee_actor.signing_principal_id().as_str();
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.principal_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS admission identity does not match the active account"
    );
    let needs_mls_admission = {
        let store = state_store.read();
        store.mls_checkpoint_for(&realm_id).is_some()
            || store.realm_projection_is_mls_encrypted(&realm_id)
    };
    if !needs_mls_admission {
        return Ok(None);
    }
    let admission_submitter = api.event_submitter()?;
    if admission_submitter
        .has_pending_mls_admission_for_realm(&realm_id)
        .await?
    {
        let advanced = admission_submitter
            .drain_mls_outbound_with_accepted_store(
                crate::app::runtime_adapter::state_store_handle(state_store),
            )
            .await?;
        tracing::warn!(
            target: "mls_admission",
            realm = %short_protocol_id(&realm_id),
            invitee = %short_protocol_id(&invitee_id),
            advanced,
            "admission deferred: drove the exact durable admission unit that already owns this Realm transition"
        );
        anyhow::bail!("an exact durable MLS admission unit is still converging for this Realm");
    }
    let pairwise_requester = {
        let store = state_store.read();
        store
            .realm_projection_is_minimal_metadata(&realm_id)
            .then(|| {
                let realm = arkret_sdk::RealmId::new(realm_id.clone())
                    .map_err(|error| format!("invalid minimal-metadata Realm id: {error}"))?;
                crate::mls::pairwise_identity::derive_pairwise_signing_material(
                    &account.authority,
                    &account.device_id,
                    &realm,
                )
            })
            .transpose()
            .map_err(anyhow::Error::msg)?
    };
    let mls_actor_id = pairwise_requester
        .as_ref()
        .map(|requester| requester.actor_id.to_string())
        .unwrap_or_else(|| actor_id.clone());
    let claim_route = if let Some(target_device_id) = target_device_id_override {
        anyhow::ensure!(
            invitee_actor == arkret_sdk::ActorId::account(account.authority.clone()),
            "device-targeted MLS admission is restricted to the active Account ActorId"
        );
        AcceptedInviteClaimRoute {
            destination_id: account.authority.station_id.to_string(),
            target_device_id: Some(target_device_id),
        }
    } else if state_store.read().realm_collaboration_role(&realm_id)
        == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
    {
        direct_contact_claim_route(&api.sdk_http_client()?, &invitee_actor).await?
    } else {
        let store = state_store.read();
        accepted_invite_claim_route(&store, &realm_id, &invitee_id).ok_or_else(|| {
            anyhow::anyhow!(
                "accepted invite has no exact destination service and accepting-device route"
            )
        })?
    };
    let target_device_id = claim_target_device_id(&claim_route, pairwise_requester.is_some())?;
    let group_id = {
        let store = state_store.read();
        store
            .mls_checkpoint_for(&realm_id)
            .map(|snapshot| snapshot.group_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "local MLS state is not ready; create or restore this device's MLS state before inviting into an encrypted Realm"
                )
            })?
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    ensure_mls_genesis_frontier_for_invite(
        api,
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &mls_actor_id,
        &device_id,
    )
    .await?;
    // Verify the current governance frontier before consuming a one-time
    // KeyPackage. The roster projection only schedules this attempt; it never
    // authorizes the claim or the resulting Add commit.
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &[],
    )
    .await?;
    // Resolve and durably retain the pre-commit epoch before allocating a
    // one-time peer package. A local export failure must not exhaust the
    // recipient's package pool on every retry.
    retain_current_history_secret_durable(
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &mls_actor_id,
        &device_id,
    )
    .await?;
    let claim_request_id = crate::mls_api_helpers::generate_mls_claim_request_id()?;
    let mls_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let claim_outcome = if let Some(requester) = pairwise_requester.as_ref() {
        mls_clients
            .mls()
            .claim_pairwise_key_package(
                invitee_principal,
                &realm_id,
                requester,
                Some(&claim_route.destination_id),
                &claim_request_id,
                None,
                &group_id,
            )
            .await?
    } else {
        mls_clients
            .mls()
            .claim_key_package(
                invitee_principal,
                &realm_id,
                &actor_id,
                &device_id,
                Some(&claim_route.destination_id),
                &claim_request_id,
                target_device_id,
                &group_id,
            )
            .await?
    };
    claim_outcome
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
    let claim_receipt = claim_outcome.claim_receipt;
    let claim = claim_outcome
        .claims
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage claim succeeded without a claim record"))?;
    anyhow::ensure!(
        crate::mls::governance_proof::claimed_actor_id(&claim, &claim_receipt)
            .map_err(anyhow::Error::msg)?
            == invitee_actor,
        "KeyPackage claim actor does not match the selected complete member ActorId"
    );
    // Refresh after the claim as well: membership/policy may have advanced
    // while the remote claim request was in flight.
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &[(&claim, &claim_receipt)],
    )
    .await?;
    let requester_device_authorize_event_id = if pairwise_requester.is_none() {
        Some(
            crate::mls::admission::current_requester_device_authorize_event_id(
                &api.sdk_http_client()?,
                &device_id,
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };
    let local_state = state_store.read().clone();
    let admission = crate::mls::admission::build_realm_mls_admission_events_from_claim(
        &local_state,
        secure_store.as_ref(),
        &realm_id,
        &account.authority,
        &mls_actor_id,
        &account.device_id,
        requester_device_authorize_event_id.as_ref(),
        &claim,
        &claim_request_id,
        &claim_receipt,
    )
    .await
    .map_err(|err| anyhow::anyhow!(err))?;
    let next_epoch = admission.snapshot.epoch;
    let invitee_device_id = claim.device_id.clone();
    // Persist the entire fail-closed admission saga before the first write.
    // The durable outbound item submits Commit first, then the exact signed
    // Welcome. Only the checkpoint-proven accepted-artifact consumer may publish
    // the snapshot/history secret. A page close between any two steps resumes
    // from the same immutable material on the next sync drain instead of
    // consuming the KeyPackage and losing the Welcome.
    api.event_submitter()?
        .submit_mls_admission_with_snapshot(
            &admission.commit,
            vec![admission.welcome],
            realm_id.clone(),
            mls_actor_id,
            device_id.clone(),
            admission.snapshot,
            &crate::app::runtime_adapter::state_store_handle(state_store),
        )
        .await?;
    tracing::debug!(
        realm = %short_protocol_id(&realm_id),
        invitee_device = %invitee_device_id
            .as_ref()
            .map(|device| short_protocol_id(device.as_str()))
            .unwrap_or_else(|| "agent".to_owned()),
        "retained local-authoritative history_secret for history-key recovery"
    );
    Ok(Some(next_epoch))
}

/// Contact Event proofs identify the peer endpoint for a founding membership,
/// which has no Realm invite/accept Event. This is only a claim selector: the
/// current signed KeyPackage claim and governance proof still authorize Add.
async fn direct_contact_claim_route(
    http: &arkret_sdk::http_client::Client,
    peer: &arkret_sdk::ActorId,
) -> anyhow::Result<AcceptedInviteClaimRoute> {
    let account = peer.as_account_id().ok_or_else(|| {
        anyhow::anyhow!("Direct Conversation human admission requires an exact AccountId")
    })?;
    let contacts = http.contacts_list().await?;
    let row = contacts
        .contacts
        .iter()
        .find(|row| row.peer.contact_actor_id() == *peer)
        .ok_or_else(|| anyhow::anyhow!("Direct Conversation peer has no accepted Contact row"))?;
    let refs = [
        row.request_event_ref.clone(),
        row.response_event_ref.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    anyhow::ensure!(
        !refs.is_empty(),
        "Contact has no accepted endpoint-bearing Event"
    );
    let resolved = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: refs.clone(),
            event_digests: Vec::new(),
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
        })
        .await?;
    let device = resolved
        .events
        .iter()
        .rev()
        .find_map(|event| {
            if event.actor_id != *peer || !refs.contains(&event.event_id) {
                return None;
            }
            let expected = event.event_id.event_digest();
            let actual = event
                .event_digest_with_digest_suite(expected.digest_suite().ok()?)
                .ok()?;
            if actual != expected.as_str() {
                return None;
            }
            garth::sync_client::accepted_human_event_signing_device(event)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Contact endpoint resolution returned {} Events, {} by the peer, {} with a device proof",
                resolved.events.len(),
                resolved.events.iter().filter(|event| event.actor_id == *peer).count(),
                resolved.events.iter().filter(|event| garth::sync_client::accepted_human_event_signing_device(event).is_some()).count(),
            )
        })?;
    Ok(AcceptedInviteClaimRoute {
        destination_id: account.station_id.to_string(),
        target_device_id: Some(device.to_string()),
    })
}

#[cfg(test)]
pub(crate) fn joined_member_signature_for_realm(store: &LocalStateStore, realm_id: &str) -> String {
    let mut dids: Vec<String> = projected_member_profiles_for_realm(store, realm_id)
        .into_iter()
        .filter(|member| member.normalized_membership() == Some("join"))
        .map(|member| member.actor_id)
        .collect();
    dids.sort();
    dids.dedup();
    dids.join(",")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum MembershipCompleteness {
    #[default]
    Unavailable,
    Limited,
    Complete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ProjectedRealmMembershipHint {
    pub(super) joined: BTreeSet<String>,
    pub(super) completeness: MembershipCompleteness,
}

/// Account-sync `members[]` is a current roster projection hint. It is more
/// suitable than the bounded raw-operation cache for reconciliation wakeups,
/// but it is not membership authority: the governance proof and server-side
/// Event auth still gate every KeyPackage claim and MLS Commit.
pub(super) fn projected_realm_membership_hint(
    store: &LocalStateStore,
    realm_id: &str,
) -> ProjectedRealmMembershipHint {
    let state = store.load();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return ProjectedRealmMembershipHint::default();
    };
    let Some(_) = projection
        .get("member_roster_entries")
        .and_then(Value::as_array)
    else {
        return ProjectedRealmMembershipHint::default();
    };
    let joined = crate::views::member_display::realm_member_roster(Some(projection))
        .into_iter()
        .filter(|member| member.membership == Some(arkret_sdk::MembershipState::Join))
        .map(|member| member.actor_id.to_string())
        .collect();
    let completeness = if projection
        .get("member_roster_entries_limited")
        .and_then(Value::as_bool)
        == Some(false)
    {
        MembershipCompleteness::Complete
    } else {
        MembershipCompleteness::Limited
    };
    ProjectedRealmMembershipHint {
        joined,
        completeness,
    }
}

pub(super) fn accepted_membership_profiles_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MemberProfile> {
    let state = store.load();
    let invitee_by_invite_id =
        local_invitee_by_invite_id_for_realm(&state.raw_operations, realm_id);
    let mut rows =
        BTreeMap::<String, (chrono::DateTime<chrono::Utc>, String, MemberProfile)>::new();
    for record in &state.raw_operations {
        if let Some(profile) =
            local_membership_profile_from_raw_operation(record, realm_id, &invitee_by_invite_id)
        {
            let actor_id = profile.actor_id.clone();
            let event_time = raw_operation_event_time(record);
            let operation_id = record.operation_id.clone();
            match rows.get(&actor_id) {
                Some((current_time, current_operation_id, _))
                    if event_time < *current_time
                        || (event_time == *current_time
                            && operation_id.as_str() <= current_operation_id.as_str()) => {}
                _ => {
                    rows.insert(actor_id, (event_time, operation_id, profile));
                }
            }
        }
    }
    rows.into_values().map(|(_, _, profile)| profile).collect()
}

pub(super) fn raw_operation_event_time(
    record: &RawOperationRecord,
) -> chrono::DateTime<chrono::Utc> {
    raw_operation_path_string(&record.payload, &["created_at"])
        .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(&timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or(record.received_at)
}

/// Admission candidates combine the positive roster hint with locally verified
/// membership state. Accepted state wins on conflict; the hint fills actors for
/// which the bounded local state-event cache has no cell and wakes reconciliation
/// when a membership-only projection arrives.
pub(super) fn admission_joined_members_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> BTreeSet<String> {
    let hint = projected_realm_membership_hint(store, realm_id);
    let mut joined = hint.joined;
    for member in accepted_membership_profiles_for_realm(store, realm_id) {
        let actor_id = member.actor_id.trim();
        if actor_id.is_empty() {
            continue;
        }
        if member.normalized_membership() == Some("join") {
            joined.insert(actor_id.to_owned());
        } else {
            joined.remove(actor_id);
        }
    }
    joined
}

pub(crate) fn realm_mls_roster_matches_complete_membership_hint(
    state_store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let Some(account) = crate::app::SessionContext::get().active_account() else {
        return false;
    };
    if account.principal_id().as_str() != actor_id || account.device_id.as_str() != device_id {
        return false;
    }
    crate::mls::runtime::realm_mls_roster_matches_complete_membership_hint(
        state_store,
        secure_store,
        realm_id,
        &account.authority,
        &account.device_id,
    )
    .unwrap_or(false)
}

pub(super) fn admission_joined_member_signature_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> String {
    admission_joined_members_for_realm(store, realm_id)
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn mls_admission_candidate_realms_for_actor(
    store: &LocalStateStore,
    actor_id: &str,
) -> Vec<(String, String)> {
    if principal_core_key(actor_id).is_none() {
        return Vec::new();
    }
    let state = store.load();
    let mut realm_ids = BTreeSet::<String>::new();
    for realm_id in state.realm_tree_projections.keys() {
        if realm_id.starts_with("ak:realm:") {
            realm_ids.insert(realm_id.clone());
        }
    }
    for realm_id in store.mls_local_checkpoints().keys() {
        if realm_id.starts_with("ak:realm:") {
            realm_ids.insert(realm_id.clone());
        }
    }
    realm_ids
        .into_iter()
        .filter(|realm_id| {
            store.mls_checkpoint_for(realm_id).is_some()
                && store.realm_projection_is_mls_encrypted(realm_id)
        })
        .map(|realm_id| {
            let joined_sig = admission_joined_member_signature_for_realm(store, &realm_id);
            (realm_id, joined_sig)
        })
        .collect()
}

/// Admin-side admission reconciliation — closes the invite-time race.
///
/// `submit_mls_admission_for_invitee` historically ran the instant an invite
/// was sent, before the invitee had accepted and published an MLS KeyPackage:
/// the claim failed, no `ak.mls.welcome` was produced, and the invitee was
/// stuck "waiting for a Welcome". This pass runs after durable Realm changes
/// and explicit deferred retries — for every Realm member who has actually
/// joined (`membership=join`) but is not yet in this
/// device's MLS group, it (re)attempts admission. Members already in the group
/// are skipped (no commit spam); members who still have not published a
/// KeyPackage are reported as deferred so the caller can apply bounded backoff.
///
/// The outcome separates completed and deferred work. That prevents an opaque
/// account cursor from being abused as a retry clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MlsAdmissionReconcileOutcome {
    pub admitted: usize,
    pub deferred: usize,
}

pub(super) fn cache_exact_accepted_realm_mls_genesis(
    store: &mut LocalStateStore,
    realm_id: &str,
) -> anyhow::Result<()> {
    let snapshot = store
        .mls_checkpoint_for(realm_id)
        .ok_or_else(|| anyhow::anyhow!("MLS admission requires a local Realm group snapshot"))?;
    // Display history may start at the recipient's join. The pinned control
    // checkpoint retains the verified Genesis needed for the installed group.
    let checkpoint = store
        .trusted_mls_governance_checkpoint(realm_id)
        .ok_or_else(|| {
            anyhow::anyhow!("MLS admission requires a verified governance checkpoint")
        })?;
    let matching = checkpoint
        .accepted_events
        .iter()
        .filter(|event| {
            event.realm_id.as_str() == realm_id
                && event.kind.as_str() == event_kind_str::MLS_GENESIS
                && matches!(
                    &event.scope_ref,
                    arkret_sdk::ScopeRef::Realm { realm_id: scope_realm }
                        if scope_realm.as_str() == realm_id
                )
                && event.payload.get("epoch").and_then(Value::as_u64) == Some(0)
                && event.payload.get("mls_group_id").and_then(Value::as_str)
                    == Some(snapshot.group_id.as_str())
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matching.len() == 1,
        "MLS admission requires exactly one accepted Realm Genesis for the local group; found {}",
        matching.len()
    );
    let accepted_genesis = serde_json::to_value(matching[0])?;
    let mut projection = store
        .load()
        .realm_tree_projections
        .get(realm_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("MLS admission requires the accepted Realm projection"))?;
    if crate::realm_tree::replace_realm_projection_mls_genesis(&mut projection, accepted_genesis) {
        store.save_realm_tree_projection(realm_id.to_owned(), projection);
    }
    Ok(())
}

pub(crate) async fn reconcile_mls_admissions_for_realm(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
) -> anyhow::Result<MlsAdmissionReconcileOutcome> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.principal_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS admission reconcile identity does not match the active account"
    );
    // A locally staged Add may already contain the peer while its durable
    // Commit/Welcome delivery is still pending. Resume that exact unit before
    // using the roster to decide there is no admission work left.
    let submitter = api.event_submitter()?;
    if submitter
        .has_pending_mls_admission_for_realm(&realm_id)
        .await?
    {
        submitter
            .drain_mls_outbound_with_accepted_store(
                crate::app::runtime_adapter::state_store_handle(state_store),
            )
            .await?;
        if submitter
            .has_pending_mls_admission_for_realm(&realm_id)
            .await?
        {
            return Ok(MlsAdmissionReconcileOutcome {
                admitted: 0,
                deferred: 1,
            });
        }
    }
    // The account projection is intentionally bounded and may expose the new
    // member count before it carries the exact `ak.invite.accept` Event. It is
    // therefore only a wake-up hint, never negative membership evidence. Read
    // the complete accepted Realm history before deciding that there is no
    // admission work; otherwise a temporarily absent projection row creates a
    // permanent pre-filter deadlock and no later Welcome can ever be authored.
    let accepted_events = api
        .event_submitter()?
        .backfill(&realm_id)
        .await?
        .complete_events("MLS admission membership reconciliation")?;
    {
        let mut store = state_store.write();
        crate::sync_engine::ingest_membership_projection_events(
            &mut store,
            &realm_id,
            &accepted_events,
        );
        cache_exact_accepted_realm_mls_genesis(&mut store, &realm_id)?;
    }
    // Only Realms this device can admit into: holding MLS state ⇒ able to build
    // the commit + Welcome. Without a snapshot we are not an admit-capable
    // member and have nothing to reconcile.
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (group_member_ids, group_device_ids): (BTreeSet<String>, BTreeSet<String>) = {
        let store = state_store.read();
        let Some(member_ids) = crate::mls::runtime::mls_group_member_actor_ids_for_effective_scope(
            &store,
            secure_store.as_ref(),
            &realm_id,
            None,
            &account.authority,
            &account.device_id,
        ) else {
            // No local group roster: either no snapshot, the device
            // snapshot secret could not be loaded, or the envelope failed
            // to decrypt. Any of these silently aborts admission — surface
            // it at WARN (wasm tracing is capped at WARN). (mls-admission-debug)
            tracing::warn!(
                target: "mls_admission",
                realm = %short_protocol_id(&realm_id),
                actor = %short_protocol_id(&actor_id),
                device = %short_protocol_id(&device_id),
                has_snapshot = state_store.read().mls_checkpoint_for(&realm_id).is_some(),
                "admission aborted: cannot read local MLS group roster (snapshot/secret/decrypt) — no member can be admitted"
            );
            return Ok(MlsAdmissionReconcileOutcome::default());
        };
        let Some(device_ids) = crate::mls::runtime::mls_group_member_device_ids_for_effective_scope(
            &store,
            secure_store.as_ref(),
            &realm_id,
            None,
            &account.authority,
            &account.device_id,
        ) else {
            tracing::warn!(
                target: "mls_admission",
                realm = %short_protocol_id(&realm_id),
                "admission aborted: cannot read local MLS endpoint roster"
            );
            return Ok(MlsAdmissionReconcileOutcome::default());
        };
        (
            member_ids
                .into_iter()
                .map(|actor| actor.to_string())
                .collect(),
            device_ids
                .into_iter()
                .map(|device| device.to_string())
                .collect(),
        )
    };
    // Joined Realm members not yet represented in the MLS group, plus current
    // same-account devices that need their own endpoint leaf. Actor membership
    // and endpoint admission are intentionally separate: deduplicating by
    // ActorId would strand every fresh device without a Welcome.
    let mut pending: Vec<(String, Option<String>)> = {
        let store = state_store.read();
        admission_joined_members_for_realm(&store, &realm_id)
            .into_iter()
            .filter(|id| {
                let id = id.trim();
                !id.is_empty()
                    && !is_local_account_actor(id, &actor_id)
                    && !group_member_ids.contains(id)
            })
            .map(|actor_id| (actor_id, None))
            .collect()
    };
    let self_actor = arkret_sdk::ActorId::account(account.authority.clone()).to_string();
    let http = api.sdk_http_client()?;
    let active_devices = crate::transport::keys::list_devices(&http).await?.devices;
    pending.extend(active_devices.into_iter().filter_map(|device| {
        (device.status == arkret_sdk::DeviceSummaryStatus::Active
            && device.device_id != account.device_id
            && !group_device_ids.contains(device.device_id.as_str()))
        .then(|| (self_actor.clone(), Some(device.device_id.to_string())))
    }));
    if pending.is_empty() {
        let local_state = state_store.read().clone();
        if local_state.realm_collaboration_role(&realm_id)
            == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
            && !local_state.direct_conversation_binding_exists(&realm_id)
            && accepted_events.iter().any(|event| {
                event.kind == arkret_sdk::EventKind::RealmCreate
                    && event.actor_id.to_string() == self_actor
            })
        {
            // Repair an unfinished endpoint handoff by an ordinary Remove/Add
            // in the existing group. A new claim still proves current authority.
            let snapshot = local_state.mls_checkpoint_for(&realm_id).ok_or_else(|| {
                anyhow::anyhow!("local Direct Conversation MLS state is unavailable")
            })?;
            let current = crate::mls::direct_binding::accepted_pair_commit(
                &accepted_events,
                &realm_id,
                &snapshot.group_id,
                snapshot.epoch,
            )?;
            for event in &accepted_events {
                if event.kind != arkret_sdk::EventKind::MlsWelcome {
                    continue;
                }
                let welcome: arkret_sdk::MlsWelcomePayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                if current.event_id != welcome.commit_ref
                    || welcome.expires_at > crate::clock::now_utc()
                {
                    continue;
                }
                let arkret_sdk::MlsWelcomeRecipient::Device {
                    recipient_device_id,
                } = welcome.recipient
                else {
                    continue;
                };
                if let Some(principal) = welcome.recipient_principal_id
                    && let Some(peer) = group_member_ids.iter().find(|peer| {
                        serde_json::from_str::<arkret_sdk::ActorId>(peer)
                            .is_ok_and(|actor| actor.signing_principal_id() == &principal)
                    })
                {
                    let route = direct_contact_claim_route(
                        &http,
                        &serde_json::from_str::<arkret_sdk::ActorId>(peer)?,
                    )
                    .await?;
                    if route.target_device_id.as_deref() == Some(recipient_device_id.as_str()) {
                        pending.push((peer.clone(), None));
                    }
                }
            }
        }
    }
    if pending.is_empty() {
        let local_state = state_store.read().clone();
        crate::mls::direct_binding::ensure_binding(api, &local_state, &realm_id, &accepted_events)
            .await?;
        return Ok(MlsAdmissionReconcileOutcome {
            admitted: 0,
            deferred: usize::from(
                local_state.realm_collaboration_role(&realm_id)
                    == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
                    && !accepted_events
                        .iter()
                        .any(|event| event.kind == arkret_sdk::EventKind::DirectConversationBound),
            ),
        });
    }
    tracing::warn!(
        target: "mls_admission",
        realm = %short_protocol_id(&realm_id),
        pending = %pending
            .iter()
            .map(|(actor, device)| device.as_deref().map_or_else(
                || short_protocol_id(actor),
                |device| format!("{}@{}", short_protocol_id(actor), short_protocol_id(device)),
            ))
            .collect::<Vec<_>>()
            .join(","),
        group_members = group_member_ids.len(),
        "admission reconcile: attempting to admit joined members not yet in MLS group"
    );
    let mut outcome = MlsAdmissionReconcileOutcome::default();
    for (invitee_id, target_device_id) in pending {
        match submit_mls_admission_for_invitee(
            api,
            state_store,
            realm_id.clone(),
            actor_id.clone(),
            device_id.clone(),
            invitee_id.clone(),
            target_device_id.clone(),
        )
        .await
        {
            Ok(Some(epoch)) => {
                outcome.admitted += 1;
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_id),
                    target_device = ?target_device_id,
                    epoch,
                    "admission succeeded: Welcome produced for invitee"
                );
            }
            Ok(None) => {
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_id),
                    target_device = ?target_device_id,
                    "admission no-op: realm not MLS-admittable from this device"
                );
            }
            // A non-fatal failure (most commonly: invitee has not published a
            // KeyPackage yet) is reported to the explicit retry scheduler.
            // Previously logged at DEBUG, which wasm tracing silences — the
            // invisible swallow is why a permanently-stuck invitee produced no
            // observable signal. Surface the actual error at WARN.
            // (mls-admission-debug)
            Err(error) => {
                outcome.deferred += 1;
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_id),
                    target_device = ?target_device_id,
                    %error,
                    "admission deferred: claim/commit/welcome step failed (bounded retry scheduled)"
                );
            }
        }
    }
    if outcome.admitted > 0 {
        // An accepted Add commit is necessary but not by itself sufficient to
        // release the send gate. Only exact agreement between the current MLS
        // roster and the complete sync hint shows that every currently
        // projected Add obligation is represented in the epoch. This only
        // resolves the locally tracked transition after an accepted Commit;
        // the hint itself is never membership or send authorization.
        let res = {
            let store = state_store.read();
            realm_mls_roster_matches_complete_membership_hint(
                &store,
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
            )
        };
        if res {
            state_store
                .write()
                .resolve_member_add_mls_bindings(&realm_id);
        }
    }
    Ok(outcome)
}

pub(super) fn mls_group_state_event_ref_ready(store: &LocalStateStore, realm_id: &str) -> bool {
    let seal_view = store.seal_view_for_realm(realm_id);
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .any(|value| arkret_sdk::EventId::new(value.clone()).is_ok())
}

pub(super) async fn ensure_mls_genesis_frontier_for_invite(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.principal_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS genesis identity does not match the active account"
    );
    {
        let store = state_store.read();
        if mls_group_state_event_ref_ready(&store, realm_id) {
            return Ok(());
        }
    }
    if let Some(event_id) = api
        .event_submitter()?
        .find_mls_genesis_event_id(realm_id)
        .await?
    {
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
            .map_err(anyhow::Error::msg)?;
        return Ok(());
    }
    {
        let store = state_store.read();
        if store.mls_genesis_emitted_for(realm_id) {
            anyhow::bail!(
                "local MLS genesis event id is not available yet; sync this Realm before inviting into its encrypted group"
            );
        }
    }
    let summary = {
        let store = state_store.read();
        crate::mls::runtime::initial_mls_checkpoint_summary_from_existing(
            &store,
            secure_store,
            realm_id,
            &account.authority,
            &account.device_id,
        )
        .map_err(|err| anyhow::anyhow!(err.user_message()))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local epoch-0 MLS snapshot is not available; create or restore this device's MLS state before inviting into an encrypted Realm"
        )
    })?;
    let leaves = crate::mls::governance_proof::singleton_security_frontier_leaf(
        &arkret_sdk::ActorId::account(account.authority.clone()),
        device_id,
    )
    .map_err(anyhow::Error::msg)?;
    let genesis_request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        None,
        summary.group_id.clone(),
        0,
        0,
        leaves.clone(),
    )
    .map_err(anyhow::Error::msg)?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof(
        api,
        crate::app::runtime_adapter::state_store_handle(state_store),
        &genesis_request,
        &leaves,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let genesis_event = {
        let mut store = state_store.write();
        crate::mls::group_events::build_creator_mls_genesis_event(
            &mut store,
            realm_id,
            actor_id,
            Some(&summary),
        )
        .map_err(|err| anyhow::anyhow!(err))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local MLS genesis event is already marked emitted but no group-state event id is available; sync this Realm before inviting"
        )
    })?;
    crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
        .await
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    match api
        .event_submitter()?
        .submit_sdk_event(&genesis_event)
        .await
    {
        Ok(accepted) => {
            // The accepted id is the only one encrypted writes may bind to.
            let event_id = arkret_sdk::EventId::new(accepted.event_id.clone())
                .map_err(|error| anyhow::anyhow!("accepted MLS genesis id invalid: {error}"))?;
            state_store
                .write()
                .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
                .map_err(anyhow::Error::msg)?;
            Ok(())
        }
        Err(err) => {
            if crate::ephemeral::events_submit_rejected_for_reason(
                &err,
                &arkret_sdk::ReasonCode::MlsGenesisAlreadyExists,
            ) {
                if let Some(event_id) = api
                    .event_submitter()?
                    .find_mls_genesis_event_id(realm_id)
                    .await?
                {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
                        .map_err(anyhow::Error::msg)?;
                    return Ok(());
                }
                anyhow::bail!(
                    "MLS genesis already exists server-side but the local event id is unavailable; sync this Realm before inviting"
                );
            }
            Err(err)
        }
    }
}

pub(super) async fn ensure_mls_governance_proof_for_next_commit(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    added_claims: &[(
        &arkret_sdk::KeyPackageClaimRecord,
        &arkret_sdk::PeerKeyPackageClaimReceipt,
    )],
) -> anyhow::Result<()> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.principal_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS governance proof identity does not match the active account"
    );
    refresh_mls_governance_target_basis(api, state_store, realm_id, added_claims).await?;
    let leaves = if added_claims.is_empty() {
        crate::mls::governance_proof::current_security_frontier_leaves(
            &state_store.read(),
            realm_id,
            None,
            &account.authority,
            &account.device_id,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| anyhow::anyhow!("invalid MLS Realm id: {error}"))?;
        let effective_scope = arkret_sdk::ScopeRef::Realm { realm_id };
        let key_packages = added_claims
            .iter()
            .map(|(claim, _)| crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim))
            .collect::<Result<Vec<_>, _>>()?;
        let target_actors = added_claims
            .iter()
            .map(|(claim, receipt)| crate::mls::governance_proof::claimed_actor_id(claim, receipt))
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::msg)?;
        crate::mls::governance_proof::preview_security_frontier_with_added_keypackages(
            &state_store.read(),
            &effective_scope,
            &account.authority,
            &account.device_id,
            &key_packages,
            &target_actors,
        )
        .map_err(anyhow::Error::msg)?
    };
    let request = {
        let store = state_store.read();
        let snapshot = store.mls_checkpoint_for(realm_id).ok_or_else(|| {
            anyhow::anyhow!("local MLS snapshot is unavailable for governance proof request")
        })?;
        crate::mls::governance_proof::proof_request(
            &store,
            realm_id,
            None,
            snapshot.group_id,
            snapshot.epoch,
            snapshot.epoch.saturating_add(1),
            leaves.clone(),
        )
        .map_err(anyhow::Error::msg)?
    };
    crate::mls::governance_proof::fetch_verify_and_cache_proof(
        api,
        crate::app::runtime_adapter::state_store_handle(state_store),
        &request,
        &leaves,
    )
    .await
    .map(|_| ())
    .map_err(anyhow::Error::msg)
}

pub(super) async fn refresh_mls_governance_target_basis(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    added_claims: &[(
        &arkret_sdk::KeyPackageClaimRecord,
        &arkret_sdk::PeerKeyPackageClaimReceipt,
    )],
) -> anyhow::Result<()> {
    const ATTEMPTS: usize = 20;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(250);

    let checkpoint = {
        let store = state_store.read();
        store
            .trusted_mls_governance_checkpoint(realm_id)
            .ok_or_else(|| anyhow::anyhow!("MLS governance checkpoint is unavailable"))?
    };
    let base_basis = checkpoint.basis.clone();
    let mut requires_membership_advance = false;
    for (claim, receipt) in added_claims {
        let Ok(actor) = crate::mls::governance_proof::claimed_actor_id(claim, receipt) else {
            requires_membership_advance = true;
            break;
        };
        if arkret_sdk::current_authorization_incarnation_from_verified_checkpoint(
            &checkpoint,
            &actor,
            None,
        )
        .await
        .is_err()
        {
            requires_membership_advance = true;
            break;
        }
    }
    let submitter = api.event_submitter()?;
    for attempt in 0..ATTEMPTS {
        match submitter.seals_frontier_realm_view(realm_id).await {
            Ok(view) if !requires_membership_advance || view.seal_basis != base_basis => {
                state_store.write().set_realm_seal_view(
                    realm_id.to_owned(),
                    crate::state::LocalSealView {
                        frontier: view
                            .seal_basis
                            .leaves
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        ..Default::default()
                    },
                );
                return Ok(());
            }
            Ok(_) if attempt + 1 < ATTEMPTS => {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Ok(_) => {
                anyhow::bail!(
                    "joined MLS Add target was not covered by a newer accepted Realm Seal frontier"
                );
            }
            Err(error)
                if attempt + 1 < ATTEMPTS
                    && crate::api_error::is_realm_seal_frontier_pending_error(&error) =>
            {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("Realm Seal frontier refresh returns on its final attempt")
}
