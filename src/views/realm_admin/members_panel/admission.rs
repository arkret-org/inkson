//! MLS admission for Realm invites.
//!
//! Reconciles accepted invites into MLS group membership: which Realms still
//! owe an admission commit, the membership completeness hint the decision
//! rests on, and the genesis/governance frontier a commit needs before it can
//! be authored. Consumed by the MLS runtime effects as well as the members
//! panel, and unrelated to how any of it is rendered.

use super::*;
pub(super) use crate::mls::admission::mls_admission_authoring_lock;

pub(crate) async fn submit_mls_admission_for_invitee(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
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
    anyhow::ensure!(
        !state_store
            .read()
            .realm_projection_has_retired_minimal_metadata_marker(&realm_id),
        "retired minimal-metadata Realm marker blocks MLS admission"
    );
    let needs_mls_admission = {
        let store = state_store.read();
        store.mls_checkpoint_for(&realm_id).is_some()
            || store.realm_projection_is_mls_encrypted(&realm_id)
    };
    if !needs_mls_admission {
        return Ok(None);
    }
    let admission_submitter = api
        .event_submitter()?
        .with_state_store(crate::app::runtime_adapter::state_store_handle(state_store));
    if admission_submitter
        .has_pending_mls_admission_for_realm(&realm_id)
        .await?
    {
        let advanced = admission_submitter.drain_mls_outbound().await?;
        tracing::warn!(
            target: "mls_admission",
            realm = %short_protocol_id(&realm_id),
            invitee = %short_protocol_id(&invitee_id),
            advanced,
            "admission deferred: drove the exact durable admission unit that already owns this Realm transition"
        );
        anyhow::bail!("an exact durable MLS admission unit is still converging for this Realm");
    }
    let mls_actor_id = actor_id.clone();
    let is_direct = state_store.read().realm_collaboration_role(&realm_id)
        == Some(arkret_sdk::CollaborationRealmRole::DirectConversation);
    let target_agent = if is_direct && target_device_id_override.is_none() {
        let http = api.sdk_http_client()?;
        match http.agent_get(invitee_principal).await {
            Ok(view) => {
                anyhow::ensure!(
                    view.agent.lifecycle == arkret_sdk::AgentLifecycleState::Active,
                    "Agent is not active"
                );
                let keys = view
                    .key_state
                    .context("Agent runtime key state is unavailable")?;
                anyhow::ensure!(
                    keys.controller_account_id == account.authority
                        && invitee_actor.route_service_id() == &account.authority.station_id,
                    "Agent claim does not belong to the current controller Account"
                );
                let key = keys
                    .active_authorizations
                    .iter()
                    .find(|key| {
                        Some(&key.authorized_event_ref) == keys.authorized_event_ref.as_ref()
                            && key
                                .expires_at
                                .is_none_or(|expiry| expiry > crate::clock::now_utc())
                    })
                    .context("Agent has no current authorized runtime key")?;
                Some(arkret_sdk::MlsEndpointIdentity::agent_runtime(
                    keys.agent_id,
                    key.verification_method.clone(),
                    key.authorized_event_ref.clone(),
                )?)
            }
            Err(arkret_sdk::http_client::Error::Api { status: 404, .. }) => None,
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    let claim_route = if target_agent.is_some() {
        AcceptedInviteClaimRoute {
            destination_id: invitee_actor.route_service_id().to_string(),
            target_device_id: None,
        }
    } else if let Some(target_device_id) = target_device_id_override {
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
    let target_device_id = if target_agent.is_some() {
        None
    } else {
        claim_target_device_id(&claim_route)?
    };
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
    let claim_request_id = crate::mls_api_helpers::generate_mls_claim_request_id()?;
    let mls_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let claim_outcome = mls_clients
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
            target_agent.as_ref(),
        )
        .await?;
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
    let local_state = state_store.read().clone();
    let admission = crate::mls::admission::build_realm_mls_admission_events_from_claim(
        &local_state,
        secure_store.as_ref(),
        &realm_id,
        &account.authority,
        &mls_actor_id,
        &account.device_id,
        &claim,
        &claim_request_id,
        &claim_receipt,
    )
    .map_err(|err| anyhow::anyhow!(err))?;
    let next_epoch = admission.staged_checkpoint.epoch;
    let invitee_device_id = claim.device_id.clone();
    let submitter = api.event_submitter()?;
    let authored_commit = submitter
        .author_for_direct_submission(&admission.commit)
        .await?;
    let welcomes = (admission.welcomes)(authored_commit.event()).map_err(anyhow::Error::msg)?;
    // The staged state contains the pending MLS Commit. Persist it before the
    // atomic authority submission so a page close after Station acceptance can
    // still merge the exact accepted epoch; the durable outbound item freezes
    // both the authored Commit and all producer-signed Welcome deliveries.
    let staged_barrier = {
        let mut store = state_store.write();
        store
            .save_mls_checkpoint(realm_id.clone(), admission.staged_checkpoint)
            .map_err(anyhow::Error::msg)?;
        store.begin_durable_flush()?
    };
    staged_barrier.wait().await?;
    submitter
        .submit_mls_commit(
            authored_commit,
            welcomes,
            account.device_id.clone(),
            admission.authority_hints,
            &crate::app::runtime_adapter::state_store_handle(state_store),
        )
        .await?;
    tracing::debug!(
        realm = %short_protocol_id(&realm_id),
        invitee_device = %invitee_device_id
            .as_ref()
            .map(|device| short_protocol_id(device.as_str()))
            .unwrap_or_else(|| "agent".to_owned()),
        "submitted MLS admission for accepted Commit and Welcome delivery"
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
    let mut resolved = Vec::with_capacity(refs.len());
    for event_id in &refs {
        if let Some(event) = http.committed_event_get(event_id).await?.reducer_input() {
            resolved.push(event.clone());
        }
    }
    let device = resolved
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
            crate::sync_parse::accepted_human_event_signing_device(event)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Contact endpoint resolution returned {} Events, {} by the peer, {} with a device proof",
                resolved.len(),
                resolved.iter().filter(|event| event.actor_id == *peer).count(),
                resolved.iter().filter(|event| crate::sync_parse::accepted_human_event_signing_device(event).is_some()).count(),
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
        .filter(|member| member.membership == Some(arkret_sdk::sync::MemberRosterMembership::Join))
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
        submitter.drain_mls_outbound().await?;
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
    let backfill = api.event_submitter()?.backfill(&realm_id).await?;
    let accepted_events = backfill.events();
    {
        let mut store = state_store.write();
        crate::sync_engine::ingest_membership_projection_events(
            &mut store,
            &realm_id,
            &accepted_events,
        );
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
    // A terminal founding claim leaves its peer leaf in the public roster.
    // Only the authenticated resolver can request its same-group replacement;
    // local roster membership, clock guesses and opaque failures cannot.
    let direct_peer = state_store.read().direct_conversation_peer(&realm_id);
    let mut direct_admission_pending = false;
    if let Some(peer) = direct_peer {
        let resolved = http
            .direct_conversation_resolve(
                &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
                    peer: peer.clone(),
                },
            )
            .await?;
        resolved.validate_shape()?;
        if let arkret_sdk::direct_conversation::DirectConversationResolveOutcome::Provisional {
            coordinates,
            peer_mls_admission,
            ..
        } = resolved
        {
            anyhow::ensure!(
                coordinates.realm_id.as_str() == realm_id,
                "Direct admission resolver changed the existing Realm"
            );
            let peer_actor = peer.contact_actor_id().to_string();
            direct_admission_pending = peer_mls_admission
                != arkret_sdk::direct_conversation::DirectConversationPeerMlsAdmission::Durable;
            if matches!(peer_mls_admission,
                arkret_sdk::direct_conversation::DirectConversationPeerMlsAdmission::Missing
                | arkret_sdk::direct_conversation::DirectConversationPeerMlsAdmission::RepairRequired)
            {
                if !pending.iter().any(|(actor, _)| actor == &peer_actor) {
                    pending.push((peer_actor, None));
                }
            } else {
                pending.retain(|(actor, _)| actor != &peer_actor);
            }
        }
    }
    let active_devices = crate::transport::keys::list_devices(&http).await?.devices;
    pending.extend(active_devices.into_iter().filter_map(|device| {
        (device.status == arkret_sdk::DeviceSummaryStatus::Active
            && device.device_id != account.device_id
            && !group_device_ids.contains(device.device_id.as_str()))
        .then(|| (self_actor.clone(), Some(device.device_id.to_string())))
    }));
    if pending.is_empty() {
        let local_state = state_store.read().clone();
        crate::mls::direct_binding::ensure_binding(api, &local_state, &realm_id, &backfill).await?;
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
        // Add acceptance does not finish Direct founding. Keep the bounded
        // resolver retry alive until durable consume permits the binding;
        // a pending claim may also become repair_required without a new Event.
        if direct_admission_pending {
            outcome.deferred += 1;
        }
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
