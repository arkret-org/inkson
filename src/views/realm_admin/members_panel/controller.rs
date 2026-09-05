//! Network commands for the Realm members panel.
//!
//! The panel's writes (invite, cancel, revoke, kick, ban, leave, agent add and
//! agent behavior) all follow the same shape: build a request from plain data,
//! submit it, then fold the outcome back into local state and one status
//! line. Keeping them here means the component only decides *when* a command
//! runs, never how it is issued or how its failure is reported.

use super::*;

pub(super) async fn fetch_realm_member_capability(
    api: &crate::transport::TransportClient,
    actor: &str,
    action: &str,
    realm: &str,
) -> anyhow::Result<bool> {
    crate::transport::realm_read::authz_check(&api.sdk_http_client()?, actor, action, realm)
        .await
        .map(|outcome| crate::transport::realm_read::authz_allowed(&outcome))
}

pub(super) async fn fetch_realm_member_capabilities(
    api: &crate::transport::TransportClient,
    actor: &str,
    realm: &str,
) -> RealmMemberPermissionChecks {
    // Keep these awaits sequential and in registry order. Each request has an
    // independent fail-closed result so one unavailable action does not hide
    // the remaining controls' decisions.
    let [
        invite_action,
        cancel_invite_action,
        revoke_invite_action,
        remove_action,
    ] = MEMBER_PERMISSION_ACTIONS;
    let invite = fetch_realm_member_capability(api, actor, invite_action, realm).await;
    let cancel_invite =
        fetch_realm_member_capability(api, actor, cancel_invite_action, realm).await;
    let revoke_invite =
        fetch_realm_member_capability(api, actor, revoke_invite_action, realm).await;
    // Member removal has no standalone capability action in v1; Realm
    // management authority is the registered fail-closed probe.
    let remove = fetch_realm_member_capability(api, actor, remove_action, realm).await;

    RealmMemberPermissionChecks {
        invite,
        cancel_invite,
        revoke_invite,
        remove,
    }
}

pub(super) async fn fetch_owned_agent_rows(
    http: &arkret_sdk::http_client::Client,
    realm: &str,
    fallback_controller_principal_id: &str,
) -> anyhow::Result<Vec<MemberAgentRow>> {
    let list = http.agent_list().await?;
    let mut rows = Vec::<MemberAgentRow>::new();
    for value in list.agent_projections {
        let Some(mut row) = member_agent_row_from_value(value, fallback_controller_principal_id)
        else {
            continue;
        };
        // Deactivated agents (lifecycle terminal) and never-keyed agents whose
        // bootstrap window lapsed (runtime_state pairing_expired) can never join
        // a Realm. Pending agents stay because Realm membership/grants are
        // independent from key pairing (key-management.md §3.6.1), although the
        // agent cannot act until it has an authorized runtime key.
        if row.status == "deactivated" || row.runtime_state == "pairing_expired" {
            continue;
        }
        match http.agent_participation_get(&row.agent_id).await {
            Ok(outcome) => {
                let (policy, selection) =
                    mention_state_from_entries(&outcome.agent_participation_entries, realm);
                row.mention_policy = policy;
                row.selection = selection;
            }
            Err(_) => {
                row.mention_policy = AgentMentionPolicy::Unknown;
            }
        }
        rows.push(row);
    }
    rows.sort_by(|left, right| {
        left.display_name
            .cmp(&right.display_name)
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });
    Ok(rows)
}

pub(super) fn spawn_set_agent_realm_behavior(
    base: String,
    api_token: String,
    realm: String,
    agent_id: String,
    selection: ParticipationBits,
    mut owned_agents: Signal<Vec<MemberAgentRow>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        let realm_id = match arkret_sdk::RealmId::new(realm.clone()) {
            Ok(realm_id) => realm_id,
            Err(err) => {
                status_msg.set(format!("invalid realm id: {err:?}"));
                return;
            }
        };
        let scope = ParticipationScope::Realm { realm_id };
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| {
            let scope = scope.clone();
            let agent_id = agent_id.clone();
            async move {
                crate::transport::account::replace_agent_participation(
                    &http, &agent_id, scope, selection,
                )
                .await
            }
        })
        .await
        {
            Ok(outcome) => {
                let (mention_policy, selection) =
                    mention_state_from_entries(&outcome.agent_participation_entries, &realm);
                owned_agents.with_mut(|rows| {
                    if let Some(row) = rows.iter_mut().find(|row| row.agent_id == outcome.agent_id)
                    {
                        row.mention_policy = mention_policy;
                        row.selection = selection;
                    }
                });
                status_msg.set(format!(
                    "Realm behavior updated for {}",
                    short_protocol_id(&outcome.agent_id)
                ));
            }
            Err(err) => status_msg.set(format!("Realm behavior update failed: {}", err.display())),
        }
    });
}

/// Recover from `invite_live_target_occupied` (`governance-objects.md` §5.3).
///
/// The Realm already holds a live directed invite for this account and the
/// submitted create was refused with zero writes. The client **MUST NOT**
/// re-sign the same create under a fresh `event_id`: the slot subject is
/// derived from the invitee account, so a new Event collides with the same
/// cell. It acts on the occupant instead, using the stable identity the
/// rejection echoed.
///
/// `pending` (and, for a third-party invite, `claimed`) means the governance
/// decision already exists and only its private delivery is missing, so the
/// delivery is re-dispatched under the occupant's own `create_event_id` — the
/// stable idempotency key, not the id of the Event that was just refused.
/// `send_failed` still occupies the slot and has no edge back to `pending`, so
/// it must be revoked before a replacement invite can be created; that revoke
/// carries the slot's `head_eq` and is what frees the account.
pub(super) async fn recover_from_occupied_live_target(
    api: &crate::transport::TransportClient,
    realm_id: &str,
    actor: &str,
    invitee: &crate::transport::InviteeResolution,
    invitee_label: &str,
    occupied: &arkret_sdk::InviteLiveTargetOccupiedProblem,
    occupant_state: Option<&str>,
) -> String {
    let invite_id = occupied.invite_id().as_str().to_owned();
    let create_event_id = occupied.create_event_id().as_str().to_owned();
    match occupant_state {
        Some(INVITE_STATE_SEND_FAILED) => {
            match crate::operation::ak_ops::invite_revoke(
                realm_id,
                actor,
                &invite_id,
                Some(invitee.account_id().principal_id.as_str()),
                "revoked",
                "delivery_target_unreachable",
            )
            .and_then(|builder| builder.build_sdk_event("inkson"))
            {
                Ok(revoke) => match api.event_submitter() {
                    Ok(submitter) => match submitter.submit_sdk_event(&revoke).await {
                        Ok(_) => format!(
                            "{invitee_label} had an undeliverable invite ({}); it was revoked. Send the invite again.",
                            short_protocol_id(&invite_id)
                        ),
                        Err(error) => format!(
                            "invite failed: {invitee_label} has an undeliverable invite ({}) that could not be revoked: {}",
                            short_protocol_id(&invite_id),
                            crate::api_error::display_user_facing(&error)
                        ),
                    },
                    Err(error) => format!(
                        "invite failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ),
                },
                Err(error) => format!("invite failed: {error:#}"),
            }
        }
        _ => match api
            .dispatch_accepted_invite(&create_event_id, invitee)
            .await
        {
            Ok(_) => format!(
                "{invitee_label} already has a live invite ({}); its private delivery was re-sent.",
                short_protocol_id(&invite_id)
            ),
            Err(error) => format!(
                "invite failed: {invitee_label} already has a live invite ({}) and re-delivery failed: {error}",
                short_protocol_id(&invite_id)
            ),
        },
    }
}

/// Server, Realm and actor every members-panel write is addressed to.
///
/// The three travelled together through every `onclick` as three separate
/// clones; naming the tuple once removes that ceremony from the view and makes
/// it impossible to submit a command against a Realm the panel is not showing.
#[derive(Clone)]
pub(super) struct RealmWriteContext {
    pub(super) base_url: String,
    pub(super) realm_id: String,
    pub(super) actor_id: String,
}

/// A membership write the panel can ask for.
///
/// Each variant carries only its own payload: the destination lives in
/// [`RealmWriteContext`] and every signal the outcome lands in lives in
/// [`RealmMembersController`]. The view therefore decides *when* a write runs
/// and never how it is issued, how local state absorbs it, or how it is
/// reported.
#[derive(Clone)]
pub(super) enum RealmMembersCommand {
    /// The signed-in account leaves the Realm.
    LeaveRealm,
    /// Admin removal: a `join` -> `leave` member state transition.
    KickMember {
        target_id: String,
        target_label: String,
    },
    /// Admin ban, which also blocks re-entry.
    BanMember {
        target_id: String,
        target_label: String,
    },
    /// Controller adds one of its own agents; agents join directly and are
    /// never invited.
    AddOwnedAgent {
        target_id: String,
        target_label: String,
    },
    /// Cancel (direct invitee known) or revoke (token / 3PID) a pending invite.
    TerminatePendingInvite {
        invite_id: String,
        member_id: String,
        member_label: String,
        /// `Some` for a direct invite, whose invitee is addressable.
        direct_invitee: Option<String>,
    },
    /// Invite already-accepted contacts through the directional Contact invite
    /// scope, one request per contact.
    InviteContacts { targets: Vec<arkret_sdk::AccountId> },
    /// Invite by typed handle / id, which must be resolved to an invitee
    /// first.
    InviteResolvedTarget {
        target: String,
        wait_for: Option<String>,
    },
}

/// Signals every members-panel write folds its outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct RealmMembersController {
    pub(super) token: Signal<String>,
    pub(super) status_msg: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) frontier_state: Signal<String>,
    pub(super) members: Signal<Vec<MemberProfile>>,
    pub(super) invite_target: Signal<String>,
    pub(super) invite_modal_open: Signal<bool>,
    pub(super) agent_add_modal_open: Signal<bool>,
    pub(super) selected_contacts: Signal<BTreeSet<String>>,
    pub(super) state_store: SyncSignal<LocalStateStore>,
}

impl RealmMembersController {
    /// Read the session credential and run `command` off the event handler.
    ///
    /// The token is sampled here rather than inside the task: an event handler
    /// is the last point at which the value is the one the user acted on.
    pub(super) fn dispatch(self, context: RealmWriteContext, command: RealmMembersCommand) {
        let token = self.token;
        let api_token = token();
        spawn(async move { self.run(context, api_token, command).await });
    }

    async fn run(
        self,
        context: RealmWriteContext,
        api_token: String,
        command: RealmMembersCommand,
    ) {
        match command {
            RealmMembersCommand::LeaveRealm => self.leave_realm(context, api_token).await,
            RealmMembersCommand::KickMember {
                target_id,
                target_label,
            } => {
                self.transition_member_out(context, api_token, target_id, target_label, false)
                    .await
            }
            RealmMembersCommand::BanMember {
                target_id,
                target_label,
            } => {
                self.transition_member_out(context, api_token, target_id, target_label, true)
                    .await
            }
            RealmMembersCommand::AddOwnedAgent {
                target_id,
                target_label,
            } => {
                self.add_owned_agent(context, api_token, target_id, target_label)
                    .await
            }
            RealmMembersCommand::TerminatePendingInvite {
                invite_id,
                member_id,
                member_label,
                direct_invitee,
            } => {
                self.terminate_pending_invite(
                    context,
                    api_token,
                    invite_id,
                    member_id,
                    member_label,
                    direct_invitee,
                )
                .await
            }
            RealmMembersCommand::InviteContacts { targets } => {
                self.invite_contacts(context, api_token, targets).await
            }
            RealmMembersCommand::InviteResolvedTarget { target, wait_for } => {
                self.invite_resolved_target(context, api_token, target, wait_for)
                    .await
            }
        }
    }

    /// Record that a membership change moved the Realm's frontier and the MLS
    /// group still owes the matching commit. Returns the suffix the status
    /// line carries when it did.
    fn note_pending_mls_binding(
        mut self,
        realm_id: &str,
        submission_key: String,
        event_id: Option<String>,
        move_kind: &str,
        reason: &str,
    ) -> &'static str {
        let mls_encrypted = self
            .state_store
            .read()
            .realm_projection_is_mls_encrypted(realm_id);
        if !mls_encrypted {
            return "";
        }
        self.state_store
            .write()
            .record_move_submission_with_event_id(
                submission_key,
                event_id,
                realm_id.to_owned(),
                move_kind,
                MoveSubmissionState::PendingMlsBinding,
                Some(reason.to_owned()),
                None,
            );
        "; epoch_update_required"
    }

    async fn leave_realm(mut self, context: RealmWriteContext, api_token: String) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let request_realm = realm_id.clone();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::realm_write::leave_realm(&sub, &request_realm, &actor_id).await
        })
        .await
        {
            Ok(_) => {
                self.state_store
                    .write()
                    .forget_realm_tree_projection(&realm_id);
                self.sync_cursor.set(String::new());
                self.status_msg
                    .set(format!("left {realm_id}; local cache cleared"));
            }
            Err(err) => self
                .status_msg
                .set(format!("leave failed: {}", err.display())),
        }
    }

    /// Kick and ban differ only in the request they issue and the word they
    /// report; both take the same member out of the roster and leave the same
    /// MLS Remove commit owing.
    async fn transition_member_out(
        mut self,
        context: RealmWriteContext,
        api_token: String,
        target_id: String,
        target_label: String,
        ban: bool,
    ) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let request_realm = realm_id.clone();
        let outcome =
            crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
                if ban {
                    crate::transport::realm_write::ban_member(
                        &sub,
                        &request_realm,
                        &actor_id,
                        &target_id,
                    )
                    .await
                } else {
                    crate::transport::realm_write::transition_member_state(
                        &sub,
                        &request_realm,
                        &actor_id,
                        &target_id,
                        Some("join"),
                        "leave",
                        "admin_kick",
                    )
                    .await
                }
            })
            .await;
        let verb = if ban { "ban" } else { "kick" };
        match outcome {
            Ok(resp) => {
                // Kick and ban historically recorded the binding under a
                // derived key with no event id; keep that shape so an existing
                // pending row is still matched by its key.
                let suffix = self.note_pending_mls_binding(
                    &realm_id,
                    format!("mls-binding:{}", resp.event_id),
                    None,
                    "mls_member_remove",
                    "epoch_update_required: membership frontier changed; MLS Remove commit \
                     required",
                );
                let past = if ban { "banned" } else { "kicked" };
                self.status_msg
                    .set(format!("{past} {target_label}{suffix}"));
            }
            Err(err) => self
                .status_msg
                .set(format!("{verb} failed: {}", err.display())),
        }
    }

    async fn add_owned_agent(
        mut self,
        context: RealmWriteContext,
        api_token: String,
        target_id: String,
        target_label: String,
    ) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let request_realm = realm_id.clone();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::realm_write::transition_member_state(
                &sub,
                &request_realm,
                &actor_id,
                &target_id,
                None,
                "join",
                "controller_add_agent",
            )
            .await
        })
        .await
        {
            Ok(resp) => {
                let suffix = self.note_pending_mls_binding(
                    &realm_id,
                    resp.event_id.clone(),
                    Some(resp.event_id.clone()),
                    "mls_member_add",
                    "epoch_update_required: agent membership frontier changed; MLS Add commit \
                     required",
                );
                self.sync_cursor.set(String::new());
                self.agent_add_modal_open.set(false);
                self.status_msg
                    .set(format!("added agent {target_label} to Realm{suffix}"));
            }
            Err(err) if crate::api_error::is_mls_keypackage_not_found_error(err.inner()) => {
                self.status_msg.set(
                    "agent add failed: Agent runtime has not completed E2EE KeyPackage publication"
                        .to_owned(),
                );
            }
            Err(err) => self
                .status_msg
                .set(format!("agent add failed: {}", err.display())),
        }
    }

    async fn terminate_pending_invite(
        mut self,
        context: RealmWriteContext,
        api_token: String,
        invite_id: String,
        member_id: String,
        member_label: String,
        direct_invitee: Option<String>,
    ) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let request_realm = realm_id.clone();
        let request_invite_id = invite_id.clone();
        let request_invitee = direct_invitee.clone();
        let is_direct = request_invitee.is_some();
        match crate::transport::auth::with_event_submitter(&base_url, api_token, |sub| async move {
            if let Some(invitee) = request_invitee {
                crate::transport::realm_write::cancel_realm_invite(
                    &sub,
                    &request_realm,
                    &actor_id,
                    &request_invite_id,
                    &invitee,
                    "revoked",
                    Some("admin_cancel"),
                )
                .await
            } else {
                crate::transport::realm_write::revoke_realm_invite(
                    &sub,
                    &request_realm,
                    &actor_id,
                    &request_invite_id,
                    None,
                    "revoked",
                    "admin_revoke",
                )
                .await
            }
        })
        .await
        {
            Ok(resp) => {
                self.frontier_state.set(resp.event_id.clone());
                self.state_store.write().append_raw_operation(
                    format!("ak:operation:{}", crate::operation::uuid_v7()),
                    Some(realm_id),
                    json!({
                        "kind": if is_direct {
                            event_kind_str::INVITE_CANCEL
                        } else {
                            event_kind_str::INVITE_REVOKE
                        },
                        "invite_id": invite_id.clone(),
                        "invitee_id": direct_invitee,
                        "state": "revoked",
                        "event_id": resp.event_id,
                    }),
                );
                let mut next_members = self.members.read().clone();
                next_members.retain(|profile| {
                    profile.invite_id.as_deref() != Some(invite_id.as_str())
                        && !(profile.actor_id == member_id && profile.is_pending_invite())
                });
                self.members.set(next_members);
                self.status_msg.set(format!(
                    "{} invite for {member_label}",
                    if is_direct { "cancelled" } else { "revoked" }
                ));
            }
            Err(err) => self
                .status_msg
                .set(format!("cancel invite failed: {}", err.display())),
        }
    }

    async fn invite_contacts(
        mut self,
        context: RealmWriteContext,
        api_token: String,
        targets: Vec<arkret_sdk::AccountId>,
    ) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let total = targets.len();
        let api = match crate::transport::auth::authed_api(&base_url, api_token) {
            Ok(api) => api,
            Err(err) => {
                self.status_msg.set(
                    crate::i18n::tr("realm_admin.invite_bad_server")
                        .replace("{error}", &err.to_string()),
                );
                return;
            }
        };
        let mut ok = 0_usize;
        let mut last_err = String::new();
        let mut ok_invites = Vec::<(arkret_sdk::AccountId, String, String)>::new();
        for account in targets {
            match api
                .invite_contact_to_realm(&realm_id, &actor_id, &account)
                .await
            {
                Ok((event_id, invite_id)) => {
                    ok += 1;
                    ok_invites.push((account, event_id.clone(), invite_id));
                    self.frontier_state.set(event_id);
                }
                Err(err) => last_err = err.to_string(),
            }
        }
        if !ok_invites.is_empty() {
            let mut next_members = self.members.read().clone();
            {
                let mut store = self.state_store.write();
                for (account, event_id, invite_id) in ok_invites {
                    let did = arkret_sdk::ActorId::account(account.clone()).to_string();
                    upsert_pending_invite_profile(&mut next_members, &did, None, Some(&invite_id));
                    store.append_raw_operation(
                        event_id.clone(),
                        Some(realm_id.clone()),
                        json!({
                            "kind": event_kind_str::INVITE_CREATE,
                            "invite_id": invite_id,
                            "invitee_account_id": account,
                            "state": "pending",
                            "event_id": event_id,
                        }),
                    );
                }
            }
            self.members.set(next_members);
        }
        self.selected_contacts.set(BTreeSet::new());
        if ok == total {
            self.invite_modal_open.set(false);
            self.status_msg
                .set(crate::i18n::tr("realm_admin.invite_sent").replace("{ok}", &ok.to_string()));
        } else {
            self.status_msg.set(
                crate::i18n::tr("realm_admin.invite_partial")
                    .replace("{ok}", &ok.to_string())
                    .replace("{total}", &total.to_string())
                    .replace("{error}", &last_err),
            );
        }
    }

    async fn invite_resolved_target(
        mut self,
        context: RealmWriteContext,
        api_token: String,
        target: String,
        wait_for: Option<String>,
    ) {
        let RealmWriteContext {
            base_url,
            realm_id,
            actor_id,
        } = context;
        let api = match authed_api_with_sync(&base_url, api_token, wait_for) {
            Ok(api) => api,
            Err(error) => {
                self.status_msg.set(format!("invalid server URL: {error}"));
                return;
            }
        };
        let invitee = match api
            .resolve_invitee_for_invite(&target, &realm_id, &actor_id)
            .await
        {
            Ok(did) => did,
            Err(error) => {
                self.status_msg.set(format!(
                    "invite target resolve failed: {}",
                    crate::api_error::display_user_facing(&error)
                ));
                return;
            }
        };
        let invitee_label = invitee
            .handle
            .clone()
            .unwrap_or_else(|| invitee.account_id().principal_id.to_string());
        let submit_event = match ak_ops::invite_create_structured(
            &realm_id,
            &actor_id,
            invitee.account_id().clone(),
            None,
            &invitee.introduction_evidence_digest,
        )
        .and_then(|builder| builder.build_sdk_event("inkson"))
        {
            Ok(event) => event,
            Err(err) => {
                self.status_msg.set(format!("invite failed: {err:#}"));
                return;
            }
        };
        // The Invite is named by its own create Event, so its id arrives with
        // the receipt.
        let op_id = submit_event.local_operation_id().to_string();
        self.status_msg
            .set(format!("submitting invite for {invitee_label}"));
        let submitted = match api.event_submitter() {
            Ok(es) => es.submit_sdk_event(&submit_event).await,
            Err(err) => Err(err),
        };
        match submitted {
            Ok(submitted) => {
                if let Err(error) = api
                    .dispatch_accepted_invite(&submitted.event_id, &invitee)
                    .await
                {
                    self.status_msg.set(format!(
                        "invite fact accepted but private delivery failed: {error}"
                    ));
                    return;
                }
                self.frontier_state.set(submitted.event_id.clone());
                // The Invite is `retype(create.event_id)`, so its id is read
                // from the accepted receipt.
                let invite_id = match arkret_sdk::EventId::new(submitted.event_id.clone()) {
                    Ok(event_id) => arkret_sdk::InviteId::from_event_id(&event_id).to_string(),
                    Err(error) => {
                        self.status_msg.set(format!(
                            "invite accepted but its Event id is invalid: {error}"
                        ));
                        return;
                    }
                };
                self.state_store.write().append_raw_operation(
                    op_id.clone(),
                    Some(realm_id),
                    json!({
                        "kind": event_kind_str::INVITE_CREATE,
                        "invite_id": invite_id.clone(),
                        "invitee_account_id": invitee.account_id().clone(),
                        "invitee_label": invitee_label.clone(),
                        "state": "pending",
                        "event_id": submitted.event_id,
                    }),
                );
                let mut next_members = self.members.read().clone();
                upsert_pending_invite_profile(
                    &mut next_members,
                    &arkret_sdk::ActorId::account(invitee.account_id().clone()).to_string(),
                    Some(&invitee_label),
                    Some(&invite_id),
                );
                self.members.set(next_members);
                self.invite_target.set(String::new());
                self.invite_modal_open.set(false);
                self.status_msg.set(format!(
                    "invited {} (pending) fact {}; MLS admission will reconcile after acceptance",
                    invitee_label,
                    short_protocol_id(&op_id)
                ));
            }
            Err(error) => {
                // A live-target collision is not a generic failure:
                // re-signing the same create under a new event_id would hit
                // the same slot again.
                let occupied = crate::api_error::invite_live_target_occupied_details(&error);
                let message = match occupied {
                    Some(occupied) => {
                        let local_state = self.state_store.read().load();
                        let occupant_state = local_invite_lifecycle_state(
                            &local_state.raw_operations,
                            &realm_id,
                            occupied.invite_id().as_str(),
                        );
                        recover_from_occupied_live_target(
                            &api,
                            &realm_id,
                            &actor_id,
                            &invitee,
                            &invitee_label,
                            &occupied,
                            occupant_state.as_deref(),
                        )
                        .await
                    }
                    None => format!(
                        "invite failed: {}",
                        crate::api_error::display_user_facing(&error)
                    ),
                };
                self.status_msg.set(message);
            }
        }
    }
}
