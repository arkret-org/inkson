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
#[derive(Clone, Copy, PartialEq)]
pub(super) struct AgentAdminController {
    pub(super) agents: Signal<Vec<AgentView>>,
    pub(super) list_status: Signal<String>,
    pub(super) last_op_status: Signal<String>,
    /// Guards against an out-of-order directory response overwriting a newer
    /// one: every refresh claims the next epoch and drops its own result once
    /// the epoch has moved on.
    pub(super) refresh_epoch: Signal<u64>,
    /// Invalidates older detail reads when a newer read or accepted pairing
    /// operation owns the row. Directory refreshes preserve loaded details.
    pub(super) detail_refresh_epoch: Signal<u64>,
    pub(super) selected_agent_id: Signal<String>,
    pub(super) create_mode: Signal<bool>,
    pub(super) new_agent_avatar_blob_ref: Signal<String>,
    /// A provision ceremony allocates several immutable identities and commit
    /// coordinates. A second click must not start a competing ceremony against
    /// the same Controller PCR authoring slot.
    pub(super) provision_in_flight: Signal<bool>,
    pub(super) deactivate_dialog_open: Signal<bool>,
    pub(super) deactivate_confirm: Signal<String>,
    /// The one Agent a pairing action is in flight for. Non-empty means every
    /// other pairing button on the panel is refused, so two renewals can never
    /// race for the same runtime key.
    pub(super) pairing_action_agent_id: Signal<String>,
    pub(super) pairing_action_phase: Signal<PairingActionPhase>,
    /// Bumped so the Contacts sidebar re-pulls `agent_list`.
    pub(super) owned_agents_rev: Signal<u64>,
    pub(super) state_store: SyncSignal<crate::state::LocalStateStore>,
}

struct ProvisionInFlightReset(Signal<bool>);

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
struct ProvisionStageDiagnostic(Option<&'static str>);

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
impl ProvisionStageDiagnostic {
    fn enter(&mut self, stage: &'static str) {
        self.0 = Some(stage);
        tracing::warn!(
            stage,
            outcome = "entered",
            "Agent provision state transition"
        );
    }

    fn complete(&mut self) {
        if let Some(stage) = self.0.take() {
            tracing::warn!(
                stage,
                outcome = "completed",
                "Agent provision state transition"
            );
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
impl Drop for ProvisionStageDiagnostic {
    fn drop(&mut self) {
        if let Some(stage) = self.0 {
            tracing::warn!(
                stage,
                outcome = "failed",
                "Agent provision state transition"
            );
        }
    }
}

impl Drop for ProvisionInFlightReset {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// The create-form values a provision run needs. They are read from the form
/// once, at click time, so a later edit cannot change the request mid-flight.
pub(super) struct ProvisionAgentRequest {
    pub(super) controller_principal_id: arkret_sdk::DidCoreId,
    pub(super) slug: String,
    pub(super) content_presets: Vec<AgentGrantPreset>,
    pub(super) service_scopes: Vec<AgentServiceScopePreset>,
}

async fn renew_agent_pairing(
    base: String,
    api_token: String,
    agent_id: String,
) -> Result<AgentRenewPairingOutcome, crate::transport::auth::ApiCallError> {
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
/// it re-pulls `agent_list`. Signal-based (not `SessionContext::get()`) because
/// callers bump from inside spawned futures, where hooks must not run; the
/// `Signal<u64>` is captured during render and moved in.
fn bump_owned_agents_rev(mut owned_agents_rev: Signal<u64>) {
    let next = owned_agents_rev.peek().saturating_add(1);
    owned_agents_rev.set(next);
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
        outcome: &AgentRenewPairingOutcome,
        track_phase: bool,
    ) -> Result<PairingReconcileOutcome, PairingReconcileError> {
        let Self {
            mut agents,
            mut last_op_status,
            mut pairing_action_phase,
            mut detail_refresh_epoch,
            ..
        } = self;
        let request_epoch = (*detail_refresh_epoch.peek()).saturating_add(1);
        detail_refresh_epoch.set(request_epoch);
        let applied = agents.with_mut(|rows| {
            apply_renewed_pairing(rows, renewed_agent_id, outcome, crate::clock::now_utc())
        });
        let reason = match applied {
            Ok(()) => return Ok(PairingReconcileOutcome::AppliedLocally),
            Err(reason) => reason,
        };
        last_op_status.set(format!(
                "A new pairing code was created, but the Agent view could not display it: {reason}. Refreshing details…"
            ));
        if track_phase {
            pairing_action_phase.set(PairingActionPhase::RefreshingAgent);
        }
        let refreshed_view = fetch_agent_details(base, api_token, renewed_agent_id)
            .await
            .map_err(|error| PairingReconcileError::RefreshFailed(error.display()))?;
        if *detail_refresh_epoch.peek() != request_epoch {
            return Err(PairingReconcileError::RefreshedViewRejected(
                "the Agent details changed while loading the pairing code",
            ));
        }
        agents
            .with_mut(|rows| {
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
        let Self {
            mut agents,
            mut list_status,
            mut refresh_epoch,
            ..
        } = self;
        let request_epoch = (*refresh_epoch.peek()).saturating_add(1);
        refresh_epoch.set(request_epoch);
        spawn(async move {
            crate::runtime_helpers::sleep_for(Duration::from_millis(1)).await;
            if api_token.trim().is_empty() {
                if *refresh_epoch.peek() != request_epoch {
                    return;
                }
                list_status.set("Sign in to load your agents.".to_owned());
                return;
            }
            match with_authed_sdk_client(&base, api_token, |http| async move {
                http.agent_list().await.map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(resp) => {
                    if *refresh_epoch.peek() != request_epoch {
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
                        list_status.set(format!("Skipped {} invalid agent row(s).", skipped,));
                    } else {
                        list_status.set(String::new());
                    }
                    agents.with_mut(|current| replace_agent_directory(current, rows));
                }
                Err(err) => {
                    if *refresh_epoch.peek() != request_epoch {
                        return;
                    }
                    list_status.set(format!("Failed to load agents: {}", err.display()));
                }
            }
        });
    }

    /// Load the authoritative detail row for one Agent and upsert it.
    pub(super) fn load_agent_details(self, base: String, api_token: String, id: String) {
        let Self {
            mut agents,
            mut last_op_status,
            mut detail_refresh_epoch,
            ..
        } = self;
        let request_epoch = (*detail_refresh_epoch.peek()).saturating_add(1);
        detail_refresh_epoch.set(request_epoch);
        spawn(async move {
            if id.trim().is_empty() {
                return;
            }
            match fetch_agent_details(&base, &api_token, &id).await {
                Ok(view) => {
                    agents.with_mut(|rows| {
                        apply_agent_detail_read(
                            rows,
                            view,
                            request_epoch,
                            *detail_refresh_epoch.peek(),
                        )
                    });
                }
                Err(err) => {
                    if *detail_refresh_epoch.peek() != request_epoch {
                        return;
                    }
                    last_op_status.set(format!("Failed to load agent details: {}", err.display()))
                }
            }
        });
    }

    /// Pause or resume an Agent. The lifecycle Event rides its own request
    /// body, so it is authored against the accepted actor frontier here
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
        let Self {
            mut agents,
            mut last_op_status,
            owned_agents_rev,
            ..
        } = self;
        spawn(async move {
            if id.is_empty() {
                return;
            }
            let Some(key_state) = key_state else {
                last_op_status.set(
                    "Agent key binding is unavailable; refresh the Agent details and retry."
                        .to_owned(),
                );
                return;
            };
            if !selected_agent_binding_matches(&id, &controller_principal_id, &key_state) {
                last_op_status.set(
                        "Agent key binding does not match the selected Agent and controller; refresh and retry."
                            .to_owned(),
                    );
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
                let pause_reason = match arkret_sdk::AuditReasonText::new("controller_paused") {
                    Ok(reason) => reason,
                    Err(error) => {
                        last_op_status.set(format!("Agent pause reason is invalid: {error}"));
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
                    last_op_status.set(format!("Agent lifecycle authoring failed: {error}"));
                    return;
                }
            };
            let result = with_event_submitter(&base, api_token, move |submitter| async move {
                let account = crate::app::SessionContext::get()
                    .active_account()
                    .ok_or_else(|| anyhow::anyhow!("active controller account is unavailable"))?;
                anyhow::ensure!(
                    account.authority == controller_account_id,
                    "active controller authority changed before lifecycle submission"
                );
                // The lifecycle Event rides its own request body rather than the
                // durable submit queue, so it is authored here and positioned by the
                // same submitter that reads the accepted actor frontier.
                let draft = submitter.author_for_direct_submission(&operation).await?;
                let lifecycle_event = submitter
                    .prepare_initial_submissions(std::slice::from_ref(&draft))
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("lifecycle submission is missing"))?;
                let outcome = if enabled {
                    let body = AgentResumeRequestBody { lifecycle_event };
                    submitter
                        .http()
                        .agent_resume(&id, &body)
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
                        .agent_pause(&id, &body)
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
                    agents.with_mut(|rows| update_agent_status(rows, &id_for_status, status));
                    bump_owned_agents_rev(owned_agents_rev);
                    let message = if enabled {
                        format!("Resumed. Status: {status_wire}.")
                    } else {
                        format!("Paused. Status: {status_wire}.")
                    };
                    last_op_status.set(message);
                }
                Err(err) => last_op_status.set(format!(
                    "{} failed: {}",
                    if enabled { "Resume" } else { "Pause" },
                    err.display()
                )),
            }
        });
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
        let Self {
            mut agents,
            mut last_op_status,
            mut deactivate_dialog_open,
            mut deactivate_confirm,
            owned_agents_rev,
            ..
        } = self;
        spawn(async move {
            if id.is_empty() {
                return;
            }
            let Some(key_state) = key_state else {
                last_op_status.set(
                    "Agent key binding is unavailable; refresh the Agent details and retry."
                        .to_owned(),
                );
                return;
            };
            if !selected_agent_binding_matches(&id, &controller_principal_id, &key_state) {
                last_op_status.set(
                        "Agent key binding does not match the selected Agent and controller; refresh and retry."
                            .to_owned(),
                    );
                return;
            }
            if status == AgentLifecycleState::Deactivated {
                last_op_status.set("Agent is already deactivated.".to_owned());
                return;
            }

            let reason = match arkret_sdk::AuditReasonText::new("controller_deactivated") {
                Ok(reason) => reason,
                Err(error) => {
                    last_op_status.set(format!("Agent deactivation reason is invalid: {error}"));
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
            // The SDK lifecycle value is the observed UI state; the Event
            // draft needs an explicit local authoring source-state decision.
            // The governing Station rechecks the actual current transition.
            let authoring_source = match status {
                AgentLifecycleState::Active => arkret_event_draft::AgentLifecycleState::Active,
                AgentLifecycleState::Paused => arkret_event_draft::AgentLifecycleState::Paused,
                AgentLifecycleState::Deactivated => {
                    last_op_status.set("Agent is already deactivated".to_owned());
                    return;
                }
            };
            let operation = match arkret_event_draft::build_agent_deactivate_intent(
                agent_actor_id.clone(),
                controller_actor_id,
                arkret_sdk::ScopeRef::Realm {
                    realm_id: key_state.principal_control_realm_id.clone(),
                },
                key_state.controller_authorization_ref.clone(),
                authoring_source,
                Some(reason.clone()),
                changed_at,
            ) {
                Ok(intent) => crate::operation::LocalOperation::new(intent),
                Err(error) => {
                    last_op_status.set(format!("Agent deactivation authoring failed: {error}"));
                    return;
                }
            };

            let id_for_status = id.clone();
            let refresh_api_token = api_token.clone();
            let result = with_event_submitter(&base, api_token, move |submitter| async move {
                let account = crate::app::SessionContext::get()
                    .active_account()
                    .ok_or_else(|| anyhow::anyhow!("active controller account is unavailable"))?;
                anyhow::ensure!(
                    account.authority == controller_account_id,
                    "active controller authority changed before lifecycle submission"
                );
                // Carried in the deactivate request body, so it is authored here
                // against the accepted actor frontier rather than queued.
                let authored = submitter.author_for_direct_submission(&operation).await?;
                let lifecycle_event = submitter
                    .prepare_initial_submissions(std::slice::from_ref(&authored))
                    .await?
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("deactivation lifecycle Event is missing"))?;
                let body = AgentDeactivateRequestBody {
                    reason: Some(reason),
                    lifecycle_event,
                };
                let outcome = submitter
                    .http()
                    .agent_deactivate(&id, &body)
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok(outcome)
            })
            .await;

            match result {
                Ok(outcome) => {
                    agents
                        .with_mut(|rows| update_agent_status(rows, &id_for_status, outcome.status));
                    bump_owned_agents_rev(owned_agents_rev);
                    // Deactivation revokes the Agent key and closes its principal-
                    // control Realm. Refreshing that Realm's Seal afterwards is
                    // both unnecessary and expected to return 404.
                    last_op_status.set("Agent deactivated permanently.".to_owned());
                    deactivate_dialog_open.set(false);
                    deactivate_confirm.set(String::new());
                }
                Err(error) => {
                    last_op_status.set(format!("Deactivate failed: {}", error.display()));
                    self.load_agent_details(base, refresh_api_token, id_for_status);
                }
            }
        });
    }

    /// Allocate a new Agent: publish its DID inception, prepare the
    /// allocation, seal the controller PCR, then commit.
    pub(super) fn provision_agent(
        self,
        base: String,
        api_token: String,
        request: ProvisionAgentRequest,
    ) {
        let Self {
            mut agents,
            mut refresh_epoch,
            mut detail_refresh_epoch,
            mut selected_agent_id,
            mut create_mode,
            mut new_agent_avatar_blob_ref,
            mut last_op_status,
            mut provision_in_flight,
            owned_agents_rev,
            state_store,
            ..
        } = self;
        if *provision_in_flight.peek() {
            last_op_status.set("Agent creation is already in progress.".to_owned());
            return;
        }
        provision_in_flight.set(true);
        let ProvisionAgentRequest {
            controller_principal_id,
            slug,
            content_presets,
            service_scopes,
        } = request;
        spawn(async move {
            let _provision_in_flight_reset = ProvisionInFlightReset(provision_in_flight);
            let account = match crate::app::SessionContext::get().active_account() {
                Some(account) => account,
                None => {
                    last_op_status
                        .set("Create failed: active controller account is unavailable".to_owned());
                    return;
                }
            };
            if account.principal_id() != &controller_principal_id {
                last_op_status.set("Create failed: active controller authority changed".to_owned());
                return;
            }
            let slug = normalize_agent_slug(&slug);
            if slug.is_empty() {
                last_op_status.set("Slug is required.".to_owned());
                return;
            }
            if let Err(error) = arkret_models_identity::validate_agent_slug(&slug) {
                last_op_status.set(format!("Slug is invalid: {error}"));
                return;
            }
            let controller_did = account.did().clone();
            let (controller_recovery_evidence, controller_station_id) = match state_store
                .read()
                .recovery_material_evidence()
            {
                Some(evidence)
                    if evidence.controller_authority.as_ref() == Some(&account.authority)
                        && evidence.principal_did == controller_did =>
                {
                    let station_id = evidence
                        .controller_authority
                        .as_ref()
                        .map(|authority| authority.station_id.clone());
                    match station_id {
                        Some(station_id) => (evidence, station_id),
                        None => unreachable!("the guarded evidence has an authority pair"),
                    }
                }
                Some(_) => {
                    last_op_status.set(
                            "Create failed: the saved controller PCR evidence does not match the signed-in identity and authority pair. Refresh identity recovery material before provisioning an Agent."
                                .to_owned(),
                        );
                    return;
                }
                None => {
                    last_op_status.set(
                            "Create failed: this device has no controller authority pair. Refresh identity recovery material before provisioning an Agent."
                                .to_owned(),
                        );
                    return;
                }
            };
            let Some(requested_scope) =
                requested_scope_for_presets(&content_presets, &service_scopes)
            else {
                last_op_status.set("Select at least one runtime service surface.".to_owned());
                return;
            };
            let nonce = crate::operation::uuid_v7();
            let agent_did_local_id = format!("agent-{nonce}");
            let operation_id = match arkret_sdk::ProtocolOperationId::new(format!(
                "ak:operation:agent.provision.{nonce}"
            )) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: operation id: {error}"));
                    return;
                }
            };
            let idempotency_key = match arkret_sdk::IdempotencyKey::new(nonce) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: idempotency key: {error}"));
                    return;
                }
            };
            let (agent_inception, agent_did_keys) = match crate::agent_identity::prepare_inception(
                &base,
                &agent_did_local_id,
                &controller_principal_id,
            ) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: Agent DID inception: {error}"));
                    return;
                }
            };
            let did = match arkret_sdk::Did::new(agent_inception.did.clone()) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: generated Agent DID: {error}"));
                    return;
                }
            };
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) = crate::agent_identity::store_keys_durable(
                secure_store.as_ref(),
                did.as_str(),
                &agent_did_keys,
            )
            .await
            {
                last_op_status.set(format!(
                    "Create failed: persist Agent DID update keys before inception: {error}"
                ));
                return;
            }
            let inception_submit = agent_inception.submit_body.clone();
            let inception_outcome =
                match with_authed_sdk_client(&base, api_token.clone(), move |http| {
                    let inception_submit = inception_submit.clone();
                    async move {
                        crate::transport::account::submit_did_operation(&http, &inception_submit)
                            .await
                    }
                })
                .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        last_op_status.set(format!(
                            "Create failed: publish Agent DID inception: {}",
                            error.display()
                        ));
                        return;
                    }
                };
            if inception_outcome.did != did {
                last_op_status.set("Create failed: inception response DID mismatch".to_owned());
                return;
            }
            if inception_outcome.status == arkret_sdk::DidOperationSubmitStatus::Pending {
                last_op_status.set(
                        "Agent DID inception is pending acceptance; retry creation after it is accepted."
                            .to_owned(),
                    );
                return;
            }
            let prepare =
                AgentProvisionRequestBody::Prepare(arkret_sdk::AgentProvisionPrepareRequestBody {
                    phase: arkret_sdk::AgentProvisionPreparePhase::Prepare,
                    operation_id: operation_id.clone(),
                    idempotency_key: idempotency_key.clone(),
                    did: did.clone(),
                    controller_station_id: controller_station_id.clone(),
                    slug: slug.clone(),
                    requested_scope: requested_scope.clone(),
                    pairing_ttl_ms: None,
                });
            let preparation = match with_authed_sdk_client(&base, api_token.clone(), move |http| {
                let prepare = prepare.clone();
                async move {
                    http.agent_provision(&prepare)
                        .await
                        .map_err(anyhow::Error::from)
                }
            })
            .await
            {
                Ok(AgentProvisionOutcome::AwaitingControllerEvent(outcome))
                    if outcome.did == did =>
                {
                    (
                        outcome.agent_id,
                        outcome.did,
                        outcome.initial_resolution,
                        outcome.controller_realm_id,
                        outcome.allocation_handle,
                        outcome.controller_authorization_ref,
                    )
                }
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis(_)) => {
                    last_op_status
                        .set("Create failed: prepare returned a committed allocation".to_owned());
                    return;
                }
                Ok(AgentProvisionOutcome::Complete(_)) => {
                    last_op_status
                        .set("Create failed: prepare returned a completed allocation".to_owned());
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingDidBinding(_)) => {
                    last_op_status.set(
                        "Create failed: prepare returned an allocation awaiting DID binding"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingControllerEvent(_)) => {
                    last_op_status
                        .set("Create failed: prepare returned a different Agent DID".to_owned());
                    return;
                }
                Err(error) => {
                    last_op_status.set(format!("Create failed: {}", error.display()));
                    return;
                }
            };
            let (
                agent_id,
                did,
                initial_resolution,
                controller_realm_id,
                allocation_handle,
                controller_authorization_ref,
            ) = preparation;
            let prepared_inception_head =
                match crate::canonical::canonical_sha256(&agent_inception.log_entry) {
                    Ok(value) => value,
                    Err(error) => {
                        last_op_status.set(format!(
                            "Create failed: digest Agent DID inception: {error}"
                        ));
                        return;
                    }
                };
            if initial_resolution.did != did
                || initial_resolution.version_id != agent_inception.version_id
                || initial_resolution.method_history_head != prepared_inception_head
            {
                last_op_status.set(
                    "Create failed: server did not pin the exact accepted Agent DID inception"
                        .to_owned(),
                );
                return;
            }
            let projected_agent_id = match arkret_sdk::project_did_to_core_id(&did) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: allocated DID: {error}"));
                    return;
                }
            };
            if projected_agent_id != agent_id {
                last_op_status.set(
                    "Create failed: allocated DID does not project to the allocated Agent ID"
                        .to_owned(),
                );
                return;
            }
            let observed_digest = match arkret_signatures::agent::agent_requested_scope_digest(
                &agent_id,
                &controller_principal_id,
                &requested_scope,
            ) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: requested scope digest: {error}"));
                    return;
                }
            };
            let expected_digest = observed_digest;
            if controller_recovery_evidence.principal_control_realm_id != controller_realm_id {
                last_op_status.set(
                        "Create failed: the server allocation controller PCR does not match this device's verified bootstrap evidence."
                            .to_owned(),
                    );
                return;
            }
            let controller_pcr_create = controller_recovery_evidence
                .pcr_genesis_unit
                .create()
                .clone();
            let controller_evidence_for_checkpoint = controller_recovery_evidence.clone();
            if let Err(error) = with_authed_api(&base, api_token.clone(), move |api| async move {
                crate::recovery_flow::verify_recovery_authority_evidence(
                    &api,
                    &controller_evidence_for_checkpoint,
                )
                .await
            })
            .await
            {
                last_op_status.set(format!(
                    "Create failed: verify Controller PCR recovery authority: {}",
                    error.display()
                ));
                return;
            }
            // Freeze and sign the exact Agent PCR create before authoring
            // the provision Event.  Its content-derived EventId is the only source
            // of the PCR Realm id carried by that provision declaration.
            let frozen_genesis = match with_event_submitter(&base, api_token.clone(), {
                let agent_id = agent_id.clone();
                let initial_resolution = initial_resolution.clone();
                let governance_station_id = controller_station_id.clone();
                let controller_principal_id = controller_principal_id.clone();
                let controller_authorization_ref = controller_authorization_ref.clone();
                move |submitter| async move {
                    let describe = submitter.service_describe().await?;
                    let draft = crate::event_builders::build_agent_pcr_create_event(
                        agent_id.as_str(),
                        initial_resolution,
                        governance_station_id,
                        controller_principal_id.as_str(),
                        controller_authorization_ref.as_str(),
                        describe.trust_domain.as_str(),
                    )?;
                    // A Agent PCR genesis is a one-Event unit: the create
                    // names the Realm, so it is authored as a unit and its shape is
                    // proven on the authored result.
                    let intent = draft.into_intent();
                    submitter
                        .author_event_unit(vec![Box::new(move |_| Ok(vec![intent]))])
                        .await?
                        .into_iter()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("prepared Agent PCR genesis is missing"))
                }
            })
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Create failed: freeze Agent PCR genesis: {}",
                        error.display()
                    ));
                    return;
                }
            };
            let principal_control_realm_id = frozen_genesis.realm_id.clone();
            // The controller is the active account, already closed in
            // `account.authority`; its Station is read from there, not from the
            // ambient authoring slot (account-lifecycle.md §156).
            if account.authority.principal_id != controller_principal_id {
                last_op_status.set(
                    "Create failed: controller principal is not the active account".to_owned(),
                );
                return;
            }
            let controller_station_id = account.authority.station_id.clone();
            let draft = match build_agent_provision_intent(
                &controller_did,
                &controller_station_id,
                &controller_realm_id,
                &agent_id,
                &principal_control_realm_id,
                &controller_authorization_ref,
                &slug,
                &expected_digest,
            ) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!("Create failed: author provision Event: {error}"));
                    return;
                }
            };
            let provision_event =
                match with_event_submitter(&base, api_token.clone(), move |submitter| async move {
                    let authored = submitter
                        .author_independent_events(vec![draft.into_intent()])
                        .await?;
                    let authored = authored
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("prepared provision Event is missing"))?;
                    submitter.prepare_authority_authored_self_principal_submission(
                        authored,
                        &controller_pcr_create,
                    )
                })
                .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        last_op_status.set(format!(
                            "Create failed: sign provision Event: {}",
                            error.display()
                        ));
                        return;
                    }
                };
            let commit =
                AgentProvisionRequestBody::Commit(arkret_sdk::AgentProvisionCommitRequestBody {
                    phase: arkret_sdk::AgentProvisionCommitPhase::Commit,
                    operation_id,
                    idempotency_key,
                    agent_id: agent_id.clone(),
                    did: did.clone(),
                    principal_control_realm_id: principal_control_realm_id.clone(),
                    allocation_handle: allocation_handle.clone(),
                    slug: slug.clone(),
                    requested_scope,
                    provision_event,
                    pairing_ttl_ms: None,
                });
            let commit_for_first_request = commit.clone();
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            let mut diagnostic = ProvisionStageDiagnostic(None);
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            diagnostic.enter("first_commit");
            match with_authed_sdk_client(&base, api_token.clone(), move |http| async move {
                http.agent_provision(&commit_for_first_request)
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis(outcome))
                    if outcome.agent_id == agent_id
                        && outcome.did == did
                        && outcome.initial_resolution == initial_resolution
                        && outcome.principal_control_realm_id == principal_control_realm_id
                        && outcome.allocation_handle == allocation_handle
                        && outcome.controller_authorization_ref == controller_authorization_ref => {
                }
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis(_)) => {
                    last_op_status.set(
                        "Create failed: commit returned mismatched PCR authoring coordinates"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::Complete(_)) => {
                    last_op_status.set(
                            "Create failed: commit completed before the declared PCR genesis was submitted"
                                .to_owned(),
                        );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingControllerEvent(_)) => {
                    last_op_status
                        .set("Create failed: commit returned another preparation".to_owned());
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingDidBinding(_)) => {
                    last_op_status.set(
                        "Create failed: commit requested DID binding before PCR acceptance"
                            .to_owned(),
                    );
                    return;
                }
                Err(error) => {
                    last_op_status.set(format!("Create failed: {}", error.display()));
                    return;
                }
            };
            let genesis_for_submit = frozen_genesis.clone();
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                diagnostic.complete();
                diagnostic.enter("genesis_submit");
            }
            if let Err(error) =
                with_event_submitter(&base, api_token.clone(), move |submitter| async move {
                    submitter
                        .submit_signed_sdk_events_in_order(std::slice::from_ref(
                            &genesis_for_submit,
                        ))
                        .await
                        .map(|_| ())
                })
                .await
            {
                last_op_status.set(format!(
                    "Agent provision accepted, but PCR genesis submission failed: {}",
                    error.display()
                ));
                return;
            }
            let commit_for_pcr_check = commit.clone();
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                diagnostic.complete();
                diagnostic.enter("pcr_commit_check");
            }
            let binding_coordinates = match with_authed_sdk_client(
                &base,
                api_token.clone(),
                move |http| async move {
                    http.agent_provision(&commit_for_pcr_check)
                        .await
                        .map_err(anyhow::Error::from)
                },
            )
            .await
            {
                Ok(AgentProvisionOutcome::AwaitingDidBinding(outcome))
                    if outcome.agent_id == agent_id
                        && outcome.did == did
                        && outcome.initial_resolution == initial_resolution
                        && outcome.principal_control_realm_id == principal_control_realm_id
                        && outcome.allocation_handle == allocation_handle
                        && outcome.controller_authorization_ref == controller_authorization_ref =>
                {
                    outcome.principal_control_realm_id
                }
                Ok(AgentProvisionOutcome::AwaitingDidBinding(_)) => {
                    last_op_status.set(
                        "Create failed: PCR acceptance returned mismatched DID-binding coordinates"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::Complete(_)) => {
                    last_op_status.set(
                            "Create failed: Agent became visible before its DID PCR binding was accepted"
                                .to_owned(),
                        );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis(_)) => {
                    last_op_status.set(
                        "Create failed: PCR genesis was accepted but provisioning did not finalize"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingControllerEvent(_)) => {
                    last_op_status
                        .set("Create failed: final commit returned another preparation".to_owned());
                    return;
                }
                Err(error) => {
                    last_op_status.set(format!("Create failed: {}", error.display()));
                    return;
                }
            };
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                diagnostic.complete();
                diagnostic.enter("did_binding_prepare");
            }
            let binding_update = match crate::agent_identity::prepare_binding_update(
                &agent_inception,
                &agent_did_keys,
                &controller_principal_id,
                &binding_coordinates,
                &expected_digest,
            ) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Create failed: build Agent DID PCR binding: {error}"
                    ));
                    return;
                }
            };
            let binding_submit = binding_update.submit_body.clone();
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                diagnostic.complete();
                diagnostic.enter("did_binding_publish");
            }
            let binding_outcome =
                match with_authed_sdk_client(&base, api_token.clone(), move |http| {
                    let binding_submit = binding_submit.clone();
                    async move {
                        crate::transport::account::submit_did_operation(&http, &binding_submit)
                            .await
                    }
                })
                .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        last_op_status.set(format!(
                            "Agent PCR accepted, but DID PCR binding publication failed: {}",
                            error.display()
                        ));
                        return;
                    }
                };
            if binding_outcome.did != did
                || binding_outcome.status == arkret_sdk::DidOperationSubmitStatus::Pending
            {
                last_op_status.set(
                    "Agent PCR accepted, but its DID binding is still pending acceptance."
                        .to_owned(),
                );
                return;
            }
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            {
                diagnostic.complete();
                diagnostic.enter("final_commit");
            }
            let outcome =
                match with_authed_sdk_client(&base, api_token.clone(), move |http| async move {
                    http.agent_provision(&commit)
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await
                {
                    Ok(AgentProvisionOutcome::Complete(outcome)) => outcome,
                    Ok(AgentProvisionOutcome::AwaitingDidBinding(_)) => {
                        last_op_status.set(
                        "Create failed: DID binding was accepted but provisioning did not finalize"
                            .to_owned(),
                    );
                        return;
                    }
                    Ok(AgentProvisionOutcome::AwaitingPcrGenesis(_)) => {
                        last_op_status.set(
                            "Create failed: final commit lost the accepted PCR genesis".to_owned(),
                        );
                        return;
                    }
                    Ok(AgentProvisionOutcome::AwaitingControllerEvent(_)) => {
                        last_op_status.set(
                            "Create failed: final commit returned another preparation".to_owned(),
                        );
                        return;
                    }
                    Err(error) => {
                        last_op_status.set(format!("Create failed: {}", error.display()));
                        return;
                    }
                };
            if outcome.agent_id != agent_id
                || outcome.did != did
                || outcome.principal_control_realm_id != principal_control_realm_id
                || outcome.controller_authorization_ref != controller_authorization_ref
            {
                last_op_status.set(
                    "Create failed: completed Agent coordinates differ from the frozen ceremony"
                        .to_owned(),
                );
                return;
            }
            #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
            diagnostic.complete();
            let created_view = match fetch_agent_details(&base, &api_token, agent_id.as_str()).await
            {
                Ok(view) => view,
                Err(error) => {
                    last_op_status.set(format!(
                        "Agent was created, but loading its authoritative details failed: {}",
                        error.display()
                    ));
                    bump_owned_agents_rev(owned_agents_rev);
                    self.refresh_agents(base, api_token);
                    return;
                }
            };
            // Older directory/detail responses must not remove or overwrite the
            // newly committed row between installing it and selecting it.
            let next_refresh_epoch = (*refresh_epoch.peek()).saturating_add(1);
            let next_detail_epoch = (*detail_refresh_epoch.peek()).saturating_add(1);
            refresh_epoch.set(next_refresh_epoch);
            detail_refresh_epoch.set(next_detail_epoch);
            let selected_id = match agents.with_mut(|rows| {
                apply_provisioned_agent_view(
                    rows,
                    created_view,
                    &outcome,
                    &controller_principal_id,
                    &account.authority.station_id,
                )
            }) {
                Ok(id) => id,
                Err(reason) => {
                    last_op_status.set(format!(
                        "Agent was created, but its authoritative details were rejected: {reason}"
                    ));
                    return;
                }
            };
            last_op_status.set(format!(
                "Created {} with a Station-committed Agent PCR.",
                short_protocol_id(agent_id.as_str())
            ));
            selected_agent_id.set(selected_id);
            create_mode.set(false);
            new_agent_avatar_blob_ref.set(String::new());
            bump_owned_agents_rev(owned_agents_rev);
            self.refresh_agents(base, api_token);
        });
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
        let Self {
            mut last_op_status,
            mut pairing_action_agent_id,
            mut pairing_action_phase,
            ..
        } = self;
        spawn(async move {
            let outcome = match renew_agent_pairing(
                base.clone(),
                api_token.clone(),
                renewed_agent_id.clone(),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    last_op_status.set(format!("Pair again failed: {}", err.display()));
                    pairing_action_agent_id.set(String::new());
                    pairing_action_phase.set(PairingActionPhase::Idle);
                    return;
                }
            };
            match self
                .reconcile_renewed_pairing(&base, &api_token, &renewed_agent_id, &outcome, true)
                .await
            {
                Ok(PairingReconcileOutcome::AppliedLocally) => last_op_status.set(format!(
                    "Pairing renewed for {}. Scan the new QR or copy the new link; the old one is dead.",
                    if slug.trim().is_empty() {
                        short_protocol_id(&renewed_agent_id)
                    } else {
                        slug.clone()
                    }
                )),
                Ok(PairingReconcileOutcome::AppliedFromAuthoritativeView) => last_op_status.set(
                    "Pairing code loaded from the authoritative Agent view.".to_owned()
                ),
                Err(PairingReconcileError::RefreshedViewRejected(reason)) => last_op_status.set(format!(
                    "The authoritative Agent view still cannot display the new pairing code: {reason}"
                )),
                Err(PairingReconcileError::RefreshFailed(error)) => last_op_status.set(format!(
                            "A new pairing code was created, but refreshing the Agent view failed: {}",
                            error
                )),
            }
            pairing_action_agent_id.set(String::new());
            pairing_action_phase.set(PairingActionPhase::Idle);
        });
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
        let Self {
            mut last_op_status, ..
        } = self;
        spawn(async move {
            let outcome = match renew_agent_pairing(
                base.clone(),
                api_token.clone(),
                replaced_agent_id.clone(),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    last_op_status.set(format!("Replace runtime failed: {}", err.display()));
                    return;
                }
            };
            match self
                .reconcile_renewed_pairing(&base, &api_token, &replaced_agent_id, &outcome, false)
                .await
            {
                Ok(PairingReconcileOutcome::AppliedLocally | PairingReconcileOutcome::AppliedFromAuthoritativeView) => {
                    last_op_status.set(
                        "Replacement pairing ready. The current runtime key is revoked the moment the new runtime pairs; the agent's lifecycle intent is unchanged.".to_owned(),
                    );
                }
                Err(PairingReconcileError::RefreshedViewRejected(reason)) => last_op_status.set(format!(
                    "A replacement pairing was created, but its credentials could not be displayed: {reason}"
                )),
                Err(PairingReconcileError::RefreshFailed(error)) => last_op_status.set(format!(
                    "A replacement pairing was created, but refreshing the Agent view failed: {error}"
                )),
            }
        });
    }
}
