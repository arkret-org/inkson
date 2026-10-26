//! Network commands for the Agent settings panel.
//!
//! Every write the panel can issue lives here as one named method on
//! [`AgentAdminController`], the bundle of Signals those writes fold their
//! outcome back into. The rsx above keeps the synchronous half of each click —
//! read the form, refuse a second in-flight pairing action, set the in-progress
//! phase — and hands the command a value; it no longer carries a hundred-line
//! `async move` block inside an `onclick`.

use super::*;

/// Signals the Agent settings writes fold their outcome back into.
#[derive(Clone)]
pub(super) struct AgentAdminController {
    pub(super) context: Rc<InksonContext>,
    pub(super) owner: glory::ui::WeakScope,
    pub(super) agents: Cage<Vec<AgentView>>,
    pub(super) list_status: Cage<String>,
    pub(super) last_op_status: Cage<String>,
    /// Guards against an out-of-order directory response overwriting a newer
    /// one: every refresh claims the next epoch and drops its own result once
    /// the epoch has moved on.
    pub(super) refresh_epoch: Cage<u64>,
    /// Invalidates older detail reads when a newer read or accepted pairing
    /// operation owns the row. Directory refreshes preserve loaded details.
    pub(super) detail_refresh_epoch: Cage<u64>,
    pub(super) selected_agent_id: Cage<String>,
    pub(super) create_mode: Cage<bool>,
    pub(super) new_agent_avatar_blob_ref: Cage<String>,
    /// A provision ceremony allocates several immutable identities and commit
    /// coordinates. A second click must not start a competing ceremony against
    /// the same Controller PCR authoring slot.
    pub(super) provision_in_flight: Cage<bool>,
    pub(super) provision_operation_id: Cage<Option<arkret_sdk::ProtocolOperationId>>,
    pub(super) deactivate_dialog_open: Cage<bool>,
    pub(super) deactivate_confirm: Cage<String>,
    /// The one Agent a pairing action is in flight for. Non-empty means every
    /// other pairing button on the panel is refused, so two renewals can never
    /// race for the same runtime key.
    pub(super) pairing_action_agent_id: Cage<String>,
    pub(super) pairing_action_phase: Cage<PairingActionPhase>,
    /// Bumped so the Contacts sidebar re-pulls `agent_page`.
    pub(super) owned_agents_rev: Cage<u64>,
    pub(super) state_store: SharedStateStore,
}

struct ProvisionInFlightReset(Cage<bool>);

impl Drop for ProvisionInFlightReset {
    fn drop(&mut self) {
        let _ = self.0.try_revise(|value| *value = false);
    }
}

/// The create-form values a provision run needs. They are read from the form
/// once, at click time, so a later edit cannot change the request mid-flight.
pub(super) struct ProvisionAgentRequest {
    pub(super) controller_principal_id: arkret_sdk::DidCoreId,
    pub(super) slug: String,
    pub(super) avatar_blob_ref: String,
    pub(super) content_presets: Vec<AgentGrantPreset>,
    pub(super) service_scopes: Vec<AgentServiceScopePreset>,
}

async fn renew_agent_pairing(
    base: String,
    api_token: String,
    agent_id: String,
) -> Result<AgentRenewPairingResponseBody, crate::transport::auth::ApiCallError> {
    with_authed_sdk_client(&base, api_token, move |http| {
        let agent_id = agent_id.clone();
        async move {
            http.agent_renew_pairing(
                &agent_id,
                &arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody::default(),
            )
            .await
            .map_err(anyhow::Error::from)
        }
    })
    .await
}

async fn fetch_agent_details(
    base: &str,
    api_token: &str,
    id: &str,
) -> Result<AgentView, crate::transport::auth::ApiCallError> {
    let id = id.to_owned();
    with_authed_sdk_client(base, api_token.to_owned(), move |http| {
        let id = id.clone();
        async move { http.agent_get(&id).await.map_err(anyhow::Error::from) }
    })
    .await
}

/// Notify the Contacts sidebar that this account's owned-agent set changed, so
/// it re-pulls `agent_page`. Signal-based (not `SessionContext::get()`) because
/// callers bump from inside spawned futures, where hooks must not run; the
/// `Cage<u64>` is captured during render and moved in.
fn bump_owned_agents_rev(owned_agents_rev: Cage<u64>) {
    let next = owned_agents_rev.get_untracked().saturating_add(1);
    owned_agents_rev.revise(|value| {
        *value = next;
    });
}

impl AgentAdminController {
    /// Apply fresh pairing material immediately when the selected row is
    /// complete; otherwise reload the authoritative detail and apply the same
    /// binding checks before replacing the local row.
    ///
    /// `track_phase` is false for the replace-runtime flow, which reports its
    /// own status text and never shows the pairing phase spinner.
    async fn reconcile_renewed_pairing(
        self,
        base: &str,
        api_token: &str,
        renewed_agent_id: &str,
        outcome: &AgentRenewPairingResponseBody,
        track_phase: bool,
    ) -> Result<PairingReconcileOutcome, PairingReconcileError> {
        let Self {
            agents,
            last_op_status,
            pairing_action_phase,
            detail_refresh_epoch,
            ..
        } = self.clone();
        let request_epoch = (detail_refresh_epoch.get_untracked()).saturating_add(1);
        detail_refresh_epoch.revise(|value| {
            let next = request_epoch;
            *value = next;
        });
        let applied = agents.revise(|rows| {
            apply_renewed_pairing(rows, renewed_agent_id, outcome, crate::clock::now_utc())
        });
        let reason = match applied {
            Ok(()) => return Ok(PairingReconcileOutcome::AppliedLocally),
            Err(reason) => reason,
        };
        last_op_status.revise(|value|{let next=format!(
                "A new pairing code was created, but the Agent view could not display it: {reason}. Refreshing details…"
            );*value=next;});
        if track_phase {
            pairing_action_phase.revise(|value| {
                let next = PairingActionPhase::RefreshingAgent;
                *value = next;
            });
        }
        let refreshed_view = fetch_agent_details(base, api_token, renewed_agent_id)
            .await
            .map_err(|error| PairingReconcileError::RefreshFailed(error.display()))?;
        if detail_refresh_epoch.get_untracked() != request_epoch {
            return Err(PairingReconcileError::RefreshedViewRejected(
                "the Agent details changed while loading the pairing code",
            ));
        }
        agents
            .revise(|rows| {
                reconcile_refreshed_pairing(
                    rows,
                    refreshed_view,
                    renewed_agent_id,
                    outcome,
                    crate::clock::now_utc(),
                )
            })
            .map_err(PairingReconcileError::RefreshedViewRejected)?;
        Ok(PairingReconcileOutcome::AppliedFromAuthoritativeView)
    }

    /// Re-pull the Agent directory, keeping any detail already loaded.
    pub(super) fn refresh_agents(self, base: String, api_token: String) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            agents,
            list_status,
            refresh_epoch,
            ..
        } = self.clone();
        let request_epoch = (refresh_epoch.get_untracked()).saturating_add(1);
        refresh_epoch.revise(|value| {
            let next = request_epoch;
            *value = next;
        });
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn(async move {
                    crate::runtime_helpers::sleep_for(Duration::from_millis(1)).await;
                    if api_token.trim().is_empty() {
                        if refresh_epoch.get_untracked() != request_epoch {
                            return;
                        }
                        list_status.revise(|value| {
                            let next = "Sign in to load your agents.".to_owned();
                            *value = next;
                        });
                        return;
                    }
                    match with_authed_sdk_client(&base, api_token, |http| async move {
                        http.agent_page().await.map_err(anyhow::Error::from)
                    })
                    .await
                    {
                        Ok(resp) => {
                            if refresh_epoch.get_untracked() != request_epoch {
                                return;
                            }
                            let total = resp.agents.len();
                            let rows: Vec<AgentView> = resp
                                .agents
                                .into_iter()
                                .filter_map(agent_view_from_directory_row)
                                .collect();
                            let skipped = total.saturating_sub(rows.len());
                            if skipped > 0 {
                                list_status.revise(|value| {
                                    let next =
                                        format!("Skipped {} invalid agent row(s).", skipped,);
                                    *value = next;
                                });
                            } else {
                                list_status.revise(|value| {
                                    let next = String::new();
                                    *value = next;
                                });
                            }
                            agents.revise(|current| replace_agent_directory(current, rows));
                        }
                        Err(err) => {
                            if refresh_epoch.get_untracked() != request_epoch {
                                return;
                            }
                            list_status.revise(|value| {
                                let next = format!("Failed to load agents: {}", err.display());
                                *value = next;
                            });
                        }
                    }
                });
            };
        };
    }

    /// Load the authoritative detail row for one Agent and upsert it.
    pub(super) fn load_agent_details(self, base: String, api_token: String, id: String) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            agents,
            last_op_status,
            detail_refresh_epoch,
            ..
        } = self.clone();
        let request_epoch = (detail_refresh_epoch.get_untracked()).saturating_add(1);
        detail_refresh_epoch.revise(|value| {
            let next = request_epoch;
            *value = next;
        });
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn(async move {
                    if id.trim().is_empty() {
                        return;
                    }
                    match fetch_agent_details(&base, &api_token, &id).await {
                        Ok(view) => {
                            agents.revise(|rows| {
                                apply_agent_detail_read(
                                    rows,
                                    view,
                                    request_epoch,
                                    detail_refresh_epoch.get_untracked(),
                                )
                            });
                        }
                        Err(err) => {
                            if detail_refresh_epoch.get_untracked() != request_epoch {
                                return;
                            }
                            last_op_status.revise(|value| {
                                let next =
                                    format!("Failed to load agent details: {}", err.display());
                                *value = next;
                            })
                        }
                    }
                });
            };
        };
    }

    /// Pause or resume an Agent. The lifecycle Event rides its own request
    /// body, so it is authored against the accepted stream head here
    /// rather than queued.
    pub(super) fn set_agent_enabled(
        self,
        base: String,
        api_token: String,
        id: String,
        controller_principal_id: arkret_sdk::DidCoreId,
        key_state: Option<KeyState>,
        enabled: bool,
    ) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            agents,
            last_op_status,
            owned_agents_rev,
            ..
        } = self.clone();
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn( async move {
                    if id.is_empty() {
                        return;
                    }
                    let Some(key_state) = key_state else {
                        last_op_status.revise(|value|{let next="Agent key binding is unavailable; refresh the Agent details and retry."
                        .to_owned();*value=next;});
                        return;
                    };
                    if !selected_agent_binding_matches(&id, &controller_principal_id, &key_state) {
                        last_op_status.revise(|value|{let next="Agent key binding does not match the selected Agent and controller; refresh and retry."
                            .to_owned();*value=next;});
                        return;
                    }
                    let id_for_status = id.clone();
                    let status_changed_at = crate::clock::now_utc_millis();
                    let controller_account_id = key_state.controller_account_id.clone();
                    let agent_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                        key_state.agent_id.clone(),
                        key_state.controller_account_id.station_id.clone(),
                    ));
                    let controller_actor_id =
                        arkret_sdk::ActorId::account(key_state.controller_account_id.clone());
                    let intent = if enabled {
                        arkret_event_draft::build_agent_resume_intent(
                            agent_actor_id.clone(),
                            controller_actor_id.clone(),
                            arkret_sdk::ScopeRef::Realm {
                                realm_id: key_state.principal_control_realm_id.clone(),
                            },
                            key_state.controller_authorization_ref.clone(),
                            status_changed_at,
                        )
                    } else {
                        let pause_reason =
                            match arkret_sdk::AuditReasonText::new("controller_paused") {
                                Ok(reason) => reason,
                                Err(error) => {
                                    last_op_status.revise(|value|{let next=format!("Agent pause reason is invalid: {error}");*value=next;});
                                    return;
                                }
                            };
                        arkret_event_draft::build_agent_pause_intent(
                            agent_actor_id.clone(),
                            controller_actor_id,
                            arkret_sdk::ScopeRef::Realm {
                                realm_id: key_state.principal_control_realm_id.clone(),
                            },
                            key_state.controller_authorization_ref.clone(),
                            Some(pause_reason),
                            status_changed_at,
                        )
                    };
                    let operation = match intent {
                        Ok(intent) => crate::operation::LocalOperation::new(intent),
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Agent lifecycle authoring failed: {error}");*value=next;});
                            return;
                        }
                    };
                    let result =
                        with_event_submitter(&base, api_token, move |submitter| async move {
                            let account = context.active_account.get().ok_or_else(|| {
                                anyhow::anyhow!("active controller account is unavailable")
                            })?;
                            anyhow::ensure!(
                                account.authority == controller_account_id,
                                "active controller authority changed before lifecycle submission"
                            );
                            // The lifecycle Event rides its own request body rather than the
                            // durable submit queue, so it is authored here and positioned by the
                            // same submitter that reads the accepted stream head.
                            let draft = submitter.author_for_direct_submission(&operation).await?;
                            let lifecycle_event = submitter
                                .prepare_initial_submissions(std::slice::from_ref(&draft))
                                .await?
                                .into_iter()
                                .next()
                                .ok_or_else(|| {
                                    anyhow::anyhow!("lifecycle submission is missing")
                                })?;
                            let outcome = if enabled {
                                let body = AgentResumeRequestBody { lifecycle_event };
                                submitter
                                    .http()
                                    .agent_resume(&id, &submitter.verify_publication(body)?)
                                    .await
                                    .map_err(anyhow::Error::from)?
                            } else {
                                let body = AgentPauseRequestBody {
                                    reason: Some(
                                        arkret_sdk::AuditReasonText::new("controller_paused")
                                            .map_err(anyhow::Error::msg)?,
                                    ),
                                    lifecycle_event,
                                };
                                submitter
                                    .http()
                                    .agent_pause(&id, &submitter.verify_publication(body)?)
                                    .await
                                    .map_err(anyhow::Error::from)?
                            };
                            Ok(outcome)
                        })
                        .await;
                    match result {
                        Ok(outcome) => {
                            let status = outcome.status;
                            let status_wire = agent_lifecycle_wire(status);
                            agents.revise(|rows| update_agent_status(rows, &id_for_status, status));
                            bump_owned_agents_rev(owned_agents_rev);
                            let message = if enabled {
                                format!("Resumed. Status: {status_wire}.")
                            } else {
                                format!("Paused. Status: {status_wire}.")
                            };
                            last_op_status.revise(|value|{let next=message;*value=next;});
                        }
                        Err(err) => last_op_status.revise(|value|{let next=format!(
                                "{} failed: {}",
                                if enabled { "Resume" } else { "Pause" },
                                err.display()
                            );*value=next;}),
                    }
                });
            };
        };
    }

    /// Deactivate an Agent permanently. Deactivation revokes the Agent key
    /// and closes its principal-control Realm, so no Seal refresh follows.
    pub(super) fn deactivate_agent(
        self,
        base: String,
        api_token: String,
        id: String,
        controller_principal_id: arkret_sdk::DidCoreId,
        status: AgentLifecycleState,
        key_state: Option<KeyState>,
    ) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            agents,
            last_op_status,
            deactivate_dialog_open,
            deactivate_confirm,
            owned_agents_rev,
            ..
        } = self.clone();
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn( async move {
                    if id.is_empty() {
                        return;
                    }
                    let Some(key_state) = key_state else {
                        last_op_status.revise(|value|{let next="Agent key binding is unavailable; refresh the Agent details and retry."
                        .to_owned();*value=next;});
                        return;
                    };
                    if !selected_agent_binding_matches(&id, &controller_principal_id, &key_state) {
                        last_op_status.revise(|value|{let next="Agent key binding does not match the selected Agent and controller; refresh and retry."
                            .to_owned();*value=next;});
                        return;
                    }
                    if status == AgentLifecycleState::Deactivated {
                        last_op_status
                            .revise(|value|{let next="Agent is already deactivated.".to_owned();*value=next;});
                        return;
                    }

                    let reason = match arkret_sdk::AuditReasonText::new("controller_deactivated") {
                        Ok(reason) => reason,
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Agent deactivation reason is invalid: {error}");*value=next;});
                            return;
                        }
                    };
                    let changed_at = crate::clock::now_utc_millis();
                    let controller_account_id = key_state.controller_account_id.clone();
                    let agent_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                        key_state.agent_id.clone(),
                        key_state.controller_account_id.station_id.clone(),
                    ));
                    let controller_actor_id =
                        arkret_sdk::ActorId::account(key_state.controller_account_id.clone());
                    if status == AgentLifecycleState::Deactivated {
                        last_op_status
                            .revise(|value|{let next="Agent is already deactivated".to_owned();*value=next;});
                        return;
                    }
                    let operation = match arkret_event_draft::build_agent_deactivate_intent(
                        agent_actor_id.clone(),
                        controller_actor_id,
                        arkret_sdk::ScopeRef::Realm {
                            realm_id: key_state.principal_control_realm_id.clone(),
                        },
                        key_state.controller_authorization_ref.clone(),
                        status,
                        Some(reason.clone()),
                        changed_at,
                    ) {
                        Ok(intent) => crate::operation::LocalOperation::new(intent),
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Agent deactivation authoring failed: {error}");*value=next;});
                            return;
                        }
                    };

                    let id_for_status = id.clone();
                    let refresh_api_token = api_token.clone();
                    let result =
                        with_event_submitter(&base, api_token, move |submitter| async move {
                            let account = context.active_account.get().ok_or_else(|| {
                                anyhow::anyhow!("active controller account is unavailable")
                            })?;
                            anyhow::ensure!(
                                account.authority == controller_account_id,
                                "active controller authority changed before lifecycle submission"
                            );
                            // Carried in the deactivate request body, so it is authored here
                            // against the accepted stream head rather than queued.
                            let authored =
                                submitter.author_for_direct_submission(&operation).await?;
                            let lifecycle_event = submitter
                                .prepare_initial_submissions(std::slice::from_ref(&authored))
                                .await?
                                .pop()
                                .ok_or_else(|| {
                                    anyhow::anyhow!("deactivation lifecycle Event is missing")
                                })?;
                            let body = AgentDeactivateRequestBody {
                                reason: Some(reason),
                                lifecycle_event,
                            };
                            let outcome = submitter
                                .http()
                                .agent_deactivate(&id, &submitter.verify_publication(body)?)
                                .await
                                .map_err(anyhow::Error::from)?;
                            Ok(outcome)
                        })
                        .await;

                    match result {
                        Ok(outcome) => {
                            agents.revise(|rows| {
                                update_agent_status(rows, &id_for_status, outcome.status)
                            });
                            bump_owned_agents_rev(owned_agents_rev);
                            // Deactivation revokes the Agent key and closes its principal-
                            // control Realm. Refreshing that Realm's Seal afterwards is
                            // both unnecessary and expected to return 404.
                            last_op_status.revise(|value|{let next="Agent deactivated permanently.".to_owned();*value=next;});
                            deactivate_dialog_open.revise(|value|{let next=false;*value=next;});
                            deactivate_confirm.revise(|value|{let next=String::new();*value=next;});
                        }
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Deactivate failed: {}", error.display());*value=next;});
                            self.clone()
                                .load_agent_details(base, refresh_api_token, id_for_status);
                        }
                    }
                });
            };
        };
    }

    /// Allocate a new Agent: publish its DID inception, prepare the
    /// allocation, seal the controller PCR, then commit.
    pub(super) fn provision_agent(
        self,
        base: String,
        api_token: String,
        request: ProvisionAgentRequest,
    ) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            last_op_status,
            provision_in_flight,
            provision_operation_id,
            state_store,
            ..
        } = self.clone();
        if provision_in_flight.get_untracked() {
            last_op_status.revise(|value| {
                let next = "Agent creation is already in progress.".to_owned();
                *value = next;
            });
            return;
        }
        let Some(account) = context.active_account.get() else {
            last_op_status.revise(|value| {
                let next = "Create failed: active controller account is unavailable".to_owned();
                *value = next;
            });
            return;
        };
        let fence = match crate::transport::auth::AuthoringSessionFence::capture() {
            Ok(fence) if fence.belongs_to_account(&account.authority) => fence,
            _ => {
                last_op_status.revise(|value| {
                    let next =
                        "Create failed: active controller authority is unavailable".to_owned();
                    *value = next;
                });
                return;
            }
        };
        provision_in_flight.revise(|value| {
            let next = true;
            *value = next;
        });
        let ProvisionAgentRequest {
            controller_principal_id,
            slug,
            avatar_blob_ref,
            content_presets,
            service_scopes,
        } = request;
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn( async move {
                    let _provision_in_flight_reset = ProvisionInFlightReset(provision_in_flight);
                    if fence.check().is_err() {
                        return;
                    }
                    if account.principal_id() != &controller_principal_id {
                        last_op_status.revise(|value|{let next="Create failed: active controller authority changed".to_owned();*value=next;});
                        return;
                    }
                    let slug = normalize_agent_slug(&slug);
                    let avatar_blob_ref = match avatar_blob_ref.trim() {
                        "" => None,
                        value => match arkret_sdk::BlobRef::new(value.to_owned()) {
                            Ok(value) => Some(value),
                            Err(error) => {
                                last_op_status.revise(|value|{let next=format!("Create failed: invalid avatar: {error}");*value=next;});
                                return;
                            }
                        },
                    };
                    if slug.is_empty() {
                        last_op_status.revise(|value|{let next="Slug is required.".to_owned();*value=next;});
                        return;
                    }
                    if let Err(error) = arkret_models_identity::validate_agent_slug(&slug) {
                        last_op_status.revise(|value|{let next=format!("Slug is invalid: {error}");*value=next;});
                        return;
                    }
                    let controller_did = account.did().clone();
                    let controller_recovery_evidence = match state_store
                        .read(|store| store.recovery_material_evidence())
                    {
                        Some(evidence)
                            if evidence.controller_authority.as_ref()
                                == Some(&account.authority)
                                && evidence.principal_did == controller_did =>
                        {
                            evidence
                        }
                        Some(_) => {
                            last_op_status.revise(|value|{let next="Create failed: the saved controller PCR evidence does not match the signed-in identity and authority pair. Refresh identity recovery material before provisioning an Agent."
                                .to_owned();*value=next;});
                            return;
                        }
                        None => {
                            last_op_status.revise(|value|{let next="Create failed: this device has no controller authority pair. Refresh identity recovery material before provisioning an Agent."
                                .to_owned();*value=next;});
                            return;
                        }
                    };
                    let Some(requested_scope) =
                        requested_scope_for_presets(&content_presets, &service_scopes)
                    else {
                        last_op_status.revise(|value|{let next="Select at least one runtime service surface.".to_owned();*value=next;});
                        return;
                    };
                    let recovery =
                        match with_authed_sdk_client(&base, api_token.clone(), |http| async move {
                            http.get::<arkret_sdk::RecoveryPolicyStatusView>(
                                "/_arkret/root/identity/recovery-policy",
                            )
                            .await
                            .map_err(anyhow::Error::from)
                        })
                        .await
                        {
                            Ok(value) => value,
                            Err(_) => {
                                last_op_status.revise(|value|{let next="Could not check your recovery policy. Refresh and try again."
                                .to_owned();*value=next;});
                                return;
                            }
                        };
                    if recovery
                        .account_id
                        .as_ref()
                        .is_some_and(|identity| identity != &account.authority)
                    {
                        last_op_status.revise(|value|{let next="The recovery policy does not match this account. Refresh and try again."
                        .to_owned();*value=next;});
                        return;
                    }
                    let Some(policy) = recovery.active_policy else {
                        last_op_status.revise(|value|{let next="Set up your recovery policy before creating an Agent.".to_owned();*value=next;});
                        return;
                    };
                    if policy.account_id != account.authority {
                        last_op_status.revise(|value|{let next="The recovery policy does not match this account. Refresh and try again."
                        .to_owned();*value=next;});
                        return;
                    }
                    if !context.active_account.get().is_some_and(|current| {
                        current.authority == account.authority && current.did() == account.did()
                    }) {
                        last_op_status.revise(|value|{let next="The active account changed. Start Agent creation again.".to_owned();*value=next;});
                        return;
                    }
                    if fence.check().is_err() {
                        return;
                    }
                    let vault = match crate::outbound_store::InksonOutboundStore::open(
                        &account.authority,
                        crate::outbound_store::OutboundLane::Standard,
                    ) {
                        Ok(vault) => vault,
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Create failed: open durable Agent intent: {error}");*value=next;});
                            return;
                        }
                    };
                    let pending = match vault.pending_agent_provisions(&account.authority).await {
                        Ok(pending) => pending,
                        Err(error) => {
                            last_op_status.revise(|value|{let next=format!("Create failed: read durable Agent intent: {error}");*value=next;});
                            return;
                        }
                    };
                    let original_id = provision_operation_id.get_untracked().clone();
                    if let Some(original_id) = original_id
                        && let Ok(saved) = vault
                            .agent_provision_record(&account.authority, &original_id)
                            .await
                        && saved.is_complete()
                    {
                        self.clone()
                            .install_completed_provision(saved, api_token, fence)
                            .await;
                        return;
                    }
                    let record = if let Some(original) = pending.into_iter().next() {
                        if original.device_id != account.device_id
                            || original.slug != slug
                            || original.avatar_blob_ref != avatar_blob_ref
                            || original.controller_did != controller_did
                            || original.principal_endpoint != base
                            || !matches!(
                                (crate::canonical::canonical_json_bytes(&original.requested_scope), crate::canonical::canonical_json_bytes(&requested_scope)),
                                (Ok(original), Ok(requested)) if original == requested
                            )
                        {
                            last_op_status.revise(|value|{let next="An original Agent creation is pending for this controller. Resume it with its original device and intent.".to_owned();*value=next;});
                            return;
                        }
                        original
                    } else {
                        let nonce = crate::operation::uuid_v7();
                        let operation_id = match arkret_sdk::ProtocolOperationId::new(format!(
                            "ak:operation:agent.provision.{nonce}"
                        )) {
                            Ok(value) => value,
                            Err(error) => {
                                last_op_status.revise(|value|{let next=format!("Create failed: operation id: {error}");*value=next;});
                                return;
                            }
                        };
                        let idempotency_key = match arkret_sdk::IdempotencyKey::new(nonce.clone()) {
                            Ok(value) => value,
                            Err(error) => {
                                last_op_status.revise(|value|{let next=format!("Create failed: idempotency key: {error}");*value=next;});
                                return;
                            }
                        };
                        let (inception, keys) = match crate::agent_identity::prepare_inception(
                            &base,
                            &format!("agent-{nonce}"),
                            &controller_principal_id,
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                last_op_status.revise(|value|{let next=format!("Create failed: Agent DID inception: {error}");*value=next;});
                                return;
                            }
                        };
                        let candidate = crate::agent_identity::provision::ProvisionCeremony {
                            authority: account.authority.clone(),
                            device_id: account.device_id.clone(),
                            controller_did,
                            principal_endpoint: base.clone(),
                            operation_id,
                            idempotency_key,
                            slug: slug.clone(),
                            avatar_blob_ref,
                            requested_scope,
                            inception,
                            keys,
                            preparation: None,
                            authored: None,
                            binding_operation: None,
                            outcome: None,
                            profile_event: None,
                            profile_commit: None,
                        };
                        match vault.freeze_agent_provision(candidate).await {
                            Ok(record) => record,
                            Err(error) => {
                                last_op_status.revise(|value|{let next=format!(
                                        "Create failed: freeze original Agent intent: {error}"
                                    );*value=next;});
                                return;
                            }
                        }
                    };
                    provision_operation_id
                        .revise(|value|{let next=Some(record.operation_id.clone());*value=next;});
                    if fence.check().is_err() {
                        return;
                    }
                    let operation_id = record.operation_id.clone();
                    let resumed = crate::agent_identity::provision::resume_ceremony(
                        record,
                        controller_recovery_evidence,
                        api_token.clone(),
                    )
                    .await;
                    if fence.check().is_err() {
                        return;
                    }
                    match resumed {
                        Ok(_) => {}
                        Err(error) => {
                            let provisioned = vault
                                .agent_provision_record(&account.authority, &operation_id)
                                .await
                                .ok()
                                .is_some_and(|saved| saved.outcome.is_some());
                            if fence.check().is_err() {
                                return;
                            }
                            last_op_status.revise(|value|{let next=if provisioned {
                        format!("Agent was created; its avatar is still pending. The original request is saved: {error}")
                    } else {
                        format!("Agent creation remains recoverable: {error}")
                    };*value=next;});
                            return;
                        }
                    }
                    match vault
                .agent_provision_record(&account.authority, &operation_id)
                .await
            {
                Ok(record) => {
                    self.clone().install_completed_provision(record, api_token, fence)
                        .await
                }
                Err(error) => last_op_status.revise(|value|{let next=format!(
                    "Agent creation is saved; reading its accepted result failed: {error}"
                );*value=next;}),
            }
                });
            };
        };
    }

    /// Observe the original journal after the route-independent worker finishes.
    /// This never provisions an Agent or authors a second profile Event.
    pub(super) fn reconcile_completed_provision(self, base: String, api_token: String) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let Some(operation_id) = self.provision_operation_id.get_untracked().clone() else {
            return;
        };
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn(async move {
                    let Ok(fence) = crate::transport::auth::AuthoringSessionFence::capture() else {
                        return;
                    };
                    let Some(account) = context.active_account.get() else {
                        return;
                    };
                    if !fence.belongs_to_account(&account.authority) {
                        return;
                    }
                    let Ok(vault) = crate::outbound_store::InksonOutboundStore::open(
                        &account.authority,
                        crate::outbound_store::OutboundLane::Standard,
                    ) else {
                        return;
                    };
                    let Ok(record) = vault
                        .agent_provision_record(&account.authority, &operation_id)
                        .await
                    else {
                        return;
                    };
                    if record.principal_endpoint == base && record.is_complete() {
                        self.clone()
                            .install_completed_provision(record, api_token, fence)
                            .await;
                    }
                });
            };
        };
    }

    async fn install_completed_provision(
        self,
        record: crate::agent_identity::provision::ProvisionCeremony,
        api_token: String,
        fence: crate::transport::auth::AuthoringSessionFence,
    ) {
        if !record.is_complete()
            || !fence.belongs_to_account(&record.authority)
            || fence.check().is_err()
            || self.provision_operation_id.get_untracked().as_ref() != Some(&record.operation_id)
        {
            return;
        }
        let Some(outcome) = record.outcome else {
            return;
        };
        let base = record.principal_endpoint;
        let Self {
            agents,
            refresh_epoch,
            detail_refresh_epoch,
            selected_agent_id,
            create_mode,
            new_agent_avatar_blob_ref,
            last_op_status,
            provision_operation_id,
            owned_agents_rev,
            ..
        } = self.clone();
        let agent_id = outcome.agent_id.clone();
        let details = fetch_agent_details(&base, &api_token, agent_id.as_str()).await;
        if fence.check().is_err()
            || provision_operation_id.get_untracked().as_ref() != Some(&record.operation_id)
        {
            return;
        }
        let created_view = match details {
            Ok(view) => view,
            Err(error) => {
                last_op_status.revise(|value| {
                    let next = format!(
                        "Agent was created, but loading its authoritative details failed: {}",
                        error.display()
                    );
                    *value = next;
                });
                self.clone().refresh_agents(base, api_token);
                return;
            }
        };
        // Older directory/detail responses must not remove or overwrite the
        // newly committed row between installing it and selecting it.
        let next_refresh_epoch = (refresh_epoch.get_untracked()).saturating_add(1);
        let next_detail_epoch = (detail_refresh_epoch.get_untracked()).saturating_add(1);
        refresh_epoch.revise(|value| {
            let next = next_refresh_epoch;
            *value = next;
        });
        detail_refresh_epoch.revise(|value| {
            let next = next_detail_epoch;
            *value = next;
        });
        let selected_id =
            match agents.revise(|rows| {
                apply_provisioned_agent_view(
                    rows,
                    created_view,
                    &outcome,
                    &record.authority.principal_id,
                    &record.authority.station_id,
                )
            }) {
                Ok(id) => id,
                Err(reason) => {
                    last_op_status.revise(|value|{let next=format!(
                    "Agent was created, but its authoritative details were rejected: {reason}"
                );*value=next;});
                    return;
                }
            };
        last_op_status.revise(|value| {
            let next = format!(
                "Created {} with a Station-committed Agent PCR.",
                short_protocol_id(agent_id.as_str())
            );
            *value = next;
        });
        selected_agent_id.revise(|value| {
            let next = selected_id;
            *value = next;
        });
        create_mode.revise(|value| {
            let next = false;
            *value = next;
        });
        new_agent_avatar_blob_ref.revise(|value| {
            let next = String::new();
            *value = next;
        });
        provision_operation_id.revise(|value| {
            let next = None;
            *value = next;
        });
        bump_owned_agents_rev(owned_agents_rev);
        self.clone().refresh_agents(base, api_token);
    }

    /// Re-open pairing on this Agent in place: fresh one-time code and QR,
    /// same principal, no replacement Agent
    /// (`ak.self.agent.command.renew_pairing.v1`).
    pub(super) fn renew_pairing(
        self,
        base: String,
        api_token: String,
        renewed_agent_id: String,
        slug: String,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self {
            last_op_status,
            pairing_action_agent_id,
            pairing_action_phase,
            ..
        } = self.clone();
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn( async move {
                    let outcome = match renew_agent_pairing(
                        base.clone(),
                        api_token.clone(),
                        renewed_agent_id.clone(),
                    )
                    .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => {
                            last_op_status.revise(|value|{let next=format!("Pair again failed: {}", err.display());*value=next;});
                            pairing_action_agent_id.revise(|value|{let next=String::new();*value=next;});
                            pairing_action_phase.revise(|value|{let next=PairingActionPhase::Idle;*value=next;});
                            return;
                        }
                    };
                    match self
                .reconcile_renewed_pairing(&base, &api_token, &renewed_agent_id, &outcome, true)
                .await
            {
                Ok(PairingReconcileOutcome::AppliedLocally) => last_op_status.revise(|value|{let next=format!(
                    "Pairing renewed for {}. Scan the new QR or copy the new link; the old one is dead.",
                    if slug.trim().is_empty() {
                        short_protocol_id(&renewed_agent_id)
                    } else {
                        slug.clone()
                    }
                );*value=next;}),
                Ok(PairingReconcileOutcome::AppliedFromAuthoritativeView) => last_op_status.revise(|value|{let next="Pairing code loaded from the authoritative Agent view.".to_owned();*value=next;}),
                Err(PairingReconcileError::RefreshedViewRejected(reason)) => last_op_status.revise(|value|{let next=format!(
                    "The authoritative Agent view still cannot display the new pairing code: {reason}"
                );*value=next;}),
                Err(PairingReconcileError::RefreshFailed(error)) => last_op_status.revise(|value|{let next=format!(
                            "A new pairing code was created, but refreshing the Agent view failed: {}",
                            error
                );*value=next;}),
            }
                    pairing_action_agent_id.revise(|value|{let next=String::new();*value=next;});
                    pairing_action_phase.revise(|value|{let next=PairingActionPhase::Idle;*value=next;});
                });
            };
        };
    }

    /// Issue a replacement pairing for an Agent that already holds an active
    /// runtime key. The current key is revoked atomically the moment the new
    /// runtime pairs, so this flow reports its own status and never shows the
    /// pairing phase spinner.
    pub(super) fn replace_runtime(
        self,
        base: String,
        api_token: String,
        replaced_agent_id: String,
    ) {
        let _context = self.context.clone();
        let owner = self.owner.clone();
        let Self { last_op_status, .. } = self.clone();
        if let Some(scope) = owner.upgrade() {
            {
                let _ = scope.owner().spawn( async move {
                    let outcome = match renew_agent_pairing(
                        base.clone(),
                        api_token.clone(),
                        replaced_agent_id.clone(),
                    )
                    .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => {
                            last_op_status.revise(|value|{let next=format!("Replace runtime failed: {}", err.display());*value=next;});
                            return;
                        }
                    };
                    match self
                .reconcile_renewed_pairing(&base, &api_token, &replaced_agent_id, &outcome, false)
                .await
            {
                Ok(PairingReconcileOutcome::AppliedLocally | PairingReconcileOutcome::AppliedFromAuthoritativeView) => {
                    last_op_status.revise(|value|{let next="Replacement pairing ready. The current runtime key is revoked the moment the new runtime pairs; the agent's lifecycle intent is unchanged.".to_owned();*value=next;});
                }
                Err(PairingReconcileError::RefreshedViewRejected(reason)) => last_op_status.revise(|value|{let next=format!(
                    "A replacement pairing was created, but its credentials could not be displayed: {reason}"
                );*value=next;}),
                Err(PairingReconcileError::RefreshFailed(error)) => last_op_status.revise(|value|{let next=format!(
                    "A replacement pairing was created, but refreshing the Agent view failed: {error}"
                );*value=next;}),
            }
                });
            };
        };
    }
}
