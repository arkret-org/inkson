//! Ephemeral hosted-view state for an Agent Sidecar.
//!
//! This state deliberately stays in memory. It carries UI context from the
//! ensure action into the source Strand shell without inventing a wire type or
//! persisting message plaintext outside the existing composer lifecycle.

use dioxus::prelude::*;

use crate::models::AccountDataSetResult;

const SIDECAR_VIEW_STATE_CACHE_PREFIX: &str = "sidecar.view_state.v1";

#[derive(Clone, Debug, PartialEq)]
pub struct HostedSidecarState {
    pub trace_id: String,
    pub controller_id: String,
    pub addressed_agent_ids: Vec<String>,
    pub addressed_agent_label: String,
    pub source_realm_id: String,
    pub source_strand_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    /// Internal effective-scope binding used by the encrypted write path. It
    /// is never rendered, routed to, or used as Sidecar identity.
    pub backing_scope_circle_id: arkret_sdk::CircleId,
    pub private_strand_id: String,
    pub private_relation_id: String,
    pub access_readiness: arkret_sdk::AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    pub mls_context: arkret_sdk::AgentSidecarMlsContext,
    pub display_mode: arkret_sdk::AgentSidecarDisplayMode,
    pub migrated_draft: String,
    pub opened_at: chrono::DateTime<chrono::Utc>,
}

impl HostedSidecarState {
    pub fn matches_route(&self, realm_id: &str, strand_id: &str) -> bool {
        self.source_realm_id == realm_id && self.source_strand_id == strand_id
    }

    pub fn membership_ready(&self) -> bool {
        self.access_readiness == arkret_sdk::AgentSidecarAccessReadiness::Ready
            && self.pending_access_reconciliations.is_empty()
            && self.mls_context.current_controller_device_ready
    }

    pub fn mls_binding(&self) -> arkret_sdk::Result<arkret_sdk::SidecarMlsBinding> {
        let binding = arkret_sdk::SidecarMlsBinding {
            sidecar_id: self.sidecar_id.clone(),
            desired_access_digest: self.mls_context.desired_access_digest.clone(),
            control_frontier: self.mls_context.control_frontier.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn pending_reconciliation_count(&self) -> usize {
        self.pending_access_reconciliations.len()
    }

    pub fn diagnostic_summary(
        &self,
        encryption_state: &str,
        message_submit_state: &str,
        notification_fanout_state: &str,
        agent_receipt_state: &str,
        last_updated: &str,
    ) -> String {
        format!(
            "Trace ID: {}\nEnsure: complete\nPrivate access: {}\nEncryption: {}\nMessage submit: {}\nNotification fanout: {}\nAgent receipt: {}\nLast updated: {}",
            self.trace_id,
            if self.membership_ready() {
                "complete".to_owned()
            } else {
                format!(
                    "reconciling ({} pending)",
                    self.pending_reconciliation_count()
                )
            },
            encryption_state,
            message_submit_state,
            notification_fanout_state,
            agent_receipt_state,
            last_updated,
        )
    }
}

fn sidecar_view_state_cache_key(controller_id: &str, realm_id: &str, strand_id: &str) -> String {
    format!("{SIDECAR_VIEW_STATE_CACHE_PREFIX}:{controller_id}:{realm_id}:{strand_id}")
}

fn cache_sidecar_view_state(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<bool> {
    let key = sidecar_view_state_cache_key(
        view_state.controller_id.as_str(),
        view_state.context_ref.realm_id.as_str(),
        view_state.context_ref.strand_id.as_str(),
    );
    let should_replace = store
        .load_private_data(account_did, &key)
        .and_then(|raw| serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok())
        .is_none_or(|current| {
            (
                view_state.updated_hlc.to_string(),
                view_state.origin_device_id.to_string(),
            ) > (
                current.updated_hlc.to_string(),
                current.origin_device_id.to_string(),
            )
        });
    if should_replace {
        store.save_private_data(account_did, key, serde_json::to_string(view_state)?);
    }
    Ok(should_replace)
}

pub fn ingest_sidecar_view_state_account_data(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    data_type: &str,
    entry: &impl serde::Serialize,
) -> anyhow::Result<bool> {
    if !data_type.starts_with("ak.agent.sidecar_view_state.v1:") {
        return Ok(false);
    }
    let view_state: arkret_sdk::AgentSidecarViewState = serde_json::from_value(
        crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)?,
    )?;
    view_state.validate_account_data_type(data_type)?;
    if view_state.controller_id.as_str() != account_did {
        anyhow::bail!("Sidecar view-state controller does not match the account holder");
    }
    cache_sidecar_view_state(store, account_did, &view_state)?;
    Ok(true)
}

fn cache_sidecar_exchange_projection(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    projection: &arkret_sdk::AgentSidecarExchangeProjection,
) -> anyhow::Result<bool> {
    projection.validate()?;
    if projection.controller_id.as_str() != account_did {
        anyhow::bail!("Sidecar exchange controller does not match the account holder");
    }
    let key = projection.account_data_type();
    let current = store.load_private_data(account_did, &key).and_then(|raw| {
        serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
    });
    let should_replace = current.as_ref().is_none_or(|current| {
        (
            projection.updated_hlc.to_string(),
            projection.client_order_key.as_str(),
        ) > (
            current.updated_hlc.to_string(),
            current.client_order_key.as_str(),
        )
    });
    if should_replace {
        store.save_private_data(account_did, key, serde_json::to_string(projection)?);
    }
    Ok(should_replace)
}

pub(crate) fn stage_sidecar_exchange_projection(
    store: &mut crate::state::LocalStateStore,
    projection: &arkret_sdk::AgentSidecarExchangeProjection,
) -> anyhow::Result<bool> {
    let controller_id = projection.controller_id.to_string();
    cache_sidecar_exchange_projection(store, &controller_id, projection)
}

pub fn ingest_sidecar_exchange_projection_account_data(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    data_type: &str,
    entry: &impl serde::Serialize,
) -> anyhow::Result<bool> {
    if !data_type.starts_with("ak.agent.sidecar_projection.v1:") {
        return Ok(false);
    }
    let projection: arkret_sdk::AgentSidecarExchangeProjection = serde_json::from_value(
        crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)?,
    )?;
    projection.validate_account_data_type(data_type)?;
    cache_sidecar_exchange_projection(store, account_did, &projection)?;
    Ok(true)
}

pub fn cached_sidecar_exchange_projections(
    store: &crate::state::LocalStateStore,
    account_did: &str,
    source_realm_id: &str,
) -> Vec<arkret_sdk::AgentSidecarExchangeProjection> {
    let prefix = format!("ak.agent.sidecar_projection.v1:{account_did}:{source_realm_id}:");
    let mut projections = store
        .private_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_private_data(account_did, &key))
        .filter_map(|raw| {
            serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
        })
        .filter(|projection| projection.validate().is_ok())
        .collect::<Vec<_>>();
    projections.sort_by(|left, right| {
        (
            left.source_hlc.to_string(),
            left.exchange_id.as_str().to_owned(),
        )
            .cmp(&(
                right.source_hlc.to_string(),
                right.exchange_id.as_str().to_owned(),
            ))
    });
    projections
}

pub async fn persist_sidecar_exchange_projection(
    base_url: &str,
    api_token: String,
    mut store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    projection: &arkret_sdk::AgentSidecarExchangeProjection,
) -> anyhow::Result<()> {
    projection.validate()?;
    let controller_id = projection.controller_id.to_string();
    let data_type = projection.account_data_type();
    let plaintext = serde_json::to_value(projection)?;
    let body =
        crate::views::settings::account_data::encrypted_account_data_value(&data_type, &plaintext)?;
    let result =
        crate::transport::auth::with_event_submitter(base_url, api_token, |submitter| async move {
            crate::transport::account::set_account_data(&submitter, &data_type, body).await
        })
        .await
        .map_err(|error| anyhow::anyhow!(error.display()))?;
    match result {
        crate::models::AccountDataSetResult::Stored { .. } => {
            cache_sidecar_exchange_projection(&mut store.write(), &controller_id, projection)?;
            Ok(())
        }
        crate::models::AccountDataSetResult::Unsupported { status } => {
            anyhow::bail!("Sidecar exchange projection account data is unsupported: {status}")
        }
    }
}

pub fn cached_sidecar_display_mode(
    store: &crate::state::LocalStateStore,
    account_did: &str,
    session: &HostedSidecarState,
) -> Option<arkret_sdk::AgentSidecarDisplayMode> {
    let key = sidecar_view_state_cache_key(
        &session.controller_id,
        &session.source_realm_id,
        &session.source_strand_id,
    );
    let view_state = store
        .load_private_data(account_did, &key)
        .and_then(|raw| serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok())?;
    (view_state.controller_id.as_str() == session.controller_id
        && view_state.sidecar_id == session.sidecar_id
        && view_state.context_ref.realm_id.as_str() == session.source_realm_id
        && view_state.context_ref.strand_id.as_str() == session.source_strand_id)
        .then_some(view_state.display_mode)
}

#[derive(Clone, Copy)]
pub struct HostedSidecarStateContext(pub Signal<Option<HostedSidecarState>>);

#[component]
pub fn HostedSidecarContextBar(base_url: String, api_token: String, device_id: String) -> Element {
    let mut hosted_state = use_context::<HostedSidecarStateContext>().0;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let Some(session) = hosted_state() else {
        return rsx! {};
    };
    let security_label = if session.membership_ready() {
        "E2EE"
    } else {
        "Reconciling access"
    };
    let merged_base = base_url.clone();
    let merged_token = api_token.clone();
    let merged_device = device_id.clone();
    let sidecar_base = base_url;
    let sidecar_token = api_token;
    let sidecar_device = device_id;

    rsx! {
        div { class: "sidecar-context-strip", "data-testid": "sidecar-context-strip",
            div { class: "sidecar-context-main",
                strong { "Private Sidecar active" }
                span { class: "muted", "Only you and your eligible AI Agents · E2EE" }
                span {
                    class: "badge sidecar-write-target",
                    "data-testid": "sidecar-write-target",
                    "data-write-target": "private",
                    "Editing: Private Sidecar"
                }
            }
            div { class: "sidecar-display-mode", role: "group", "aria-label": "Private Sidecar display mode",
                button {
                    r#type: "button",
                    class: if session.display_mode == arkret_sdk::AgentSidecarDisplayMode::ContextMerged { "active" } else { "" },
                    "data-testid": "sidecar-mode-context-merged",
                    onclick: move |_| {
                        if let Some(mut current) = hosted_state() {
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::ContextMerged;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                merged_base.clone(),
                                merged_token.clone(),
                                current.controller_id.clone(),
                                merged_device.clone(),
                                &current,
                            );
                            hosted_state.set(Some(current));
                        }
                    },
                    "Original Strand + Sidecar"
                }
                button {
                    r#type: "button",
                    class: if session.display_mode == arkret_sdk::AgentSidecarDisplayMode::SidecarOnly { "active" } else { "" },
                    "data-testid": "sidecar-mode-sidecar-only",
                    onclick: move |_| {
                        if let Some(mut current) = hosted_state() {
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::SidecarOnly;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                sidecar_base.clone(),
                                sidecar_token.clone(),
                                current.controller_id.clone(),
                                sidecar_device.clone(),
                                &current,
                            );
                            hosted_state.set(Some(current));
                        }
                    },
                    "Sidecar only"
                }
                button {
                    r#type: "button",
                    "data-testid": "sidecar-exit",
                    onclick: move |_| hosted_state.set(None),
                    "Exit Private Sidecar"
                }
            }
            div { class: "sidecar-addressed-now", "data-testid": "sidecar-addressed-now",
                span { class: "muted", "Addressed now" }
                strong { "{session.addressed_agent_label}" }
                span { class: "badge", "{security_label}" }
            }
        }
    }
}

/// Best-effort encrypted cross-device persistence for the hosted Strand-level
/// display mode. The local signal is authoritative for the current frame; a
/// failed network write is retried naturally by a later user change/account
/// stream reconciliation and never mutates shared Strand state.
pub fn push_sidecar_display_mode(
    store: &mut crate::state::LocalStateStore,
    base_url: String,
    api_token: String,
    controller_id: String,
    device_id: String,
    session: &HostedSidecarState,
) {
    let context_ref = match (
        arkret_sdk::RealmId::new(session.source_realm_id.clone()),
        arkret_sdk::StrandId::new(session.source_strand_id.clone()),
        arkret_sdk::Did::new(controller_id.clone()),
        arkret_sdk::DeviceId::new(device_id.clone()),
    ) {
        (Ok(realm_id), Ok(strand_id), Ok(controller_id), Ok(origin_device_id)) => {
            (realm_id, strand_id, controller_id, origin_device_id)
        }
        _ => {
            tracing::warn!("Sidecar view-state contains an invalid typed identifier");
            return;
        }
    };
    let control_realm_id = arkret_sdk::principal_control_realm_id(&context_ref.2);
    let updated_hlc = match crate::signing_stamp::issue_protocol_hlc(
        context_ref.2.as_str(),
        context_ref.3.as_str(),
        &control_realm_id,
    ) {
        Ok(hlc) => hlc,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state HLC allocation failed");
            return;
        }
    };
    let view_state = arkret_sdk::AgentSidecarViewState {
        schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
        controller_id: context_ref.2,
        sidecar_id: session.sidecar_id.clone(),
        context_ref: arkret_sdk::AgentSidecarStrandContextRef {
            realm_id: context_ref.0,
            strand_id: context_ref.1,
        },
        display_mode: session.display_mode,
        pinned: None,
        collapsed: None,
        updated_hlc,
        origin_device_id: context_ref.3,
    };
    let data_type = view_state.account_data_type();
    if let Err(error) = cache_sidecar_view_state(store, &controller_id, &view_state) {
        tracing::warn!(%error, "Sidecar view-state local cache failed");
    }
    let plaintext = match serde_json::to_value(&view_state) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state serialization failed");
            return;
        }
    };
    let body = match crate::views::settings::account_data::encrypted_account_data_value(
        &data_type, &plaintext,
    ) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state encryption failed");
            return;
        }
    };
    spawn(async move {
        match crate::transport::auth::with_event_submitter(
            &base_url,
            api_token,
            |submitter| async move {
                crate::transport::account::set_account_data(&submitter, &data_type, body).await
            },
        )
        .await
        {
            Ok(AccountDataSetResult::Stored { .. }) => {}
            Ok(AccountDataSetResult::Unsupported { status }) => {
                tracing::warn!(%status, "Sidecar view-state account data is unsupported");
            }
            Err(error) => {
                tracing::warn!(error = %error.display(), "Sidecar view-state sync failed")
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(
        pending: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    ) -> HostedSidecarState {
        HostedSidecarState {
            trace_id: "019f0000-0000-7000-8000-000000000001".to_owned(),
            controller_id: "did:web:alice.example".to_owned(),
            addressed_agent_ids: vec!["did:web:agents.example:assistant".to_owned()],
            addressed_agent_label: "Assistant".to_owned(),
            source_realm_id: "ak:realm:019f0000-0000-7000-8000-000000000002".to_owned(),
            source_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000003".to_owned(),
            sidecar_id: arkret_sdk::SidecarId::new(
                "ak:sidecar:019f0000-0000-7000-8000-000000000004".to_owned(),
            )
            .unwrap(),
            backing_scope_circle_id: arkret_sdk::CircleId::new(
                "ak:circle:019f0000-0000-7000-8000-000000000007".to_owned(),
            )
            .unwrap(),
            private_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000005".to_owned(),
            private_relation_id: "ak:relation:019f0000-0000-7000-8000-000000000006".to_owned(),
            access_readiness: if pending.is_empty() {
                arkret_sdk::AgentSidecarAccessReadiness::Ready
            } else {
                arkret_sdk::AgentSidecarAccessReadiness::AccessReconciliationPending
            },
            pending_access_reconciliations: pending,
            mls_context: arkret_sdk::AgentSidecarMlsContext {
                desired_access_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                control_frontier: vec![
                    arkret_sdk::NonEmptyString::new(
                        "ak:event:019f0000-0000-7000-8000-000000000005",
                    )
                    .unwrap(),
                ],
                mls_group_id: None,
                epoch: None,
                genesis_event_ref: None,
                current_controller_device_ready: false,
            },
            display_mode: arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            migrated_draft: String::new(),
            opened_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn pending_reconciliation_is_not_ready() {
        let session = session(vec![arkret_sdk::PendingSidecarAccessReconciliationItem {
            agent_id: arkret_sdk::Did::new("did:web:agents.example:assistant").unwrap(),
            stage: arkret_sdk::PendingSidecarAccessReconciliationStage::BackingScopeMembership,
            reason: arkret_sdk::NonEmptyString::new("membership_projection_pending").unwrap(),
            membership_frontier: None,
        }]);
        assert!(!session.membership_ready());
        assert_eq!(session.pending_reconciliation_count(), 1);
        assert!(
            session
                .diagnostic_summary(
                    "Reconciling access",
                    "not started",
                    "not started",
                    "not reported",
                    "12:00:00",
                )
                .contains("reconciling (1 pending)")
        );
    }

    #[test]
    fn sidecar_readiness_and_mls_binding_require_the_current_device() {
        let mut session = session(Vec::new());
        assert!(!session.membership_ready());
        session.mls_context.current_controller_device_ready = true;
        assert!(session.membership_ready());

        let binding = session.mls_binding().unwrap();
        assert_eq!(binding.sidecar_id, session.sidecar_id);
        assert_eq!(
            binding.desired_access_digest,
            session.mls_context.desired_access_digest
        );
        assert_eq!(
            binding.control_frontier,
            session.mls_context.control_frontier
        );
    }

    #[test]
    fn route_match_requires_realm_and_source_strand() {
        let session = session(Vec::new());
        assert!(session.matches_route(&session.source_realm_id, &session.source_strand_id));
        assert!(!session.matches_route(&session.source_realm_id, &session.private_strand_id));
    }

    #[test]
    fn sidecar_view_state_cache_is_lww_and_context_scoped() {
        let account = "did:web:alice.example";
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-view-state-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(path);
        let session = session(Vec::new());
        let view_state = |mode, hlc: &str, device: &str| arkret_sdk::AgentSidecarViewState {
            schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
            controller_id: arkret_sdk::Did::new(account).unwrap(),
            sidecar_id: session.sidecar_id.clone(),
            context_ref: arkret_sdk::AgentSidecarStrandContextRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
            },
            display_mode: mode,
            pinned: None,
            collapsed: None,
            updated_hlc: arkret_sdk::Hlc::new(hlc).unwrap(),
            origin_device_id: arkret_sdk::DeviceId::new(device).unwrap(),
        };
        let newer = view_state(
            arkret_sdk::AgentSidecarDisplayMode::SidecarOnly,
            "01970e589d21-0002-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000001",
        );
        let older = view_state(
            arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            "01970e589d21-0001-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000002",
        );

        assert!(cache_sidecar_view_state(&mut store, account, &newer).unwrap());
        assert!(!cache_sidecar_view_state(&mut store, account, &older).unwrap());
        assert_eq!(
            cached_sidecar_display_mode(&store, account, &session),
            Some(arkret_sdk::AgentSidecarDisplayMode::SidecarOnly)
        );
    }

    #[test]
    fn sidecar_exchange_cache_is_per_exchange_lww_and_controller_bound() {
        let account = "did:web:alice.example";
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-exchange-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(path);
        let session = session(Vec::new());
        let mut projection = arkret_sdk::AgentSidecarExchangeProjection {
            schema: arkret_sdk::AgentSidecarExchangeProjectionSchema::V1,
            controller_id: arkret_sdk::Did::new(account).unwrap(),
            sidecar_id: session.sidecar_id.clone(),
            private_strand_id: arkret_sdk::StrandId::new(session.private_strand_id.clone())
                .unwrap(),
            exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
                .unwrap(),
            origin: arkret_sdk::AgentSidecarExchangeOrigin::SourceTrackRouted,
            source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_frontier_anchor: None,
            source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![
                arkret_sdk::Did::new("did:web:agents.example:assistant").unwrap(),
            ],
            participating_agent_ids: Vec::new(),
            private_request_event_id: arkret_sdk::EventId::new(
                "ak:event:01964137-0000-7000-8000-000000000009",
            )
            .unwrap(),
            user_facing_response_event_ids: Vec::new(),
            status: arkret_sdk::AgentSidecarExchangeStatus::Pending,
            failure_code: None,
            updated_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        };

        assert!(stage_sidecar_exchange_projection(&mut store, &projection).unwrap());
        projection.status = arkret_sdk::AgentSidecarExchangeStatus::Delivered;
        projection.updated_hlc = arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap();
        assert!(stage_sidecar_exchange_projection(&mut store, &projection).unwrap());

        let cached =
            cached_sidecar_exchange_projections(&store, account, session.source_realm_id.as_str());
        assert_eq!(cached, vec![projection.clone()]);
        assert!(
            cache_sidecar_exchange_projection(&mut store, "did:web:bob.example", &projection,)
                .is_err()
        );
    }
}
