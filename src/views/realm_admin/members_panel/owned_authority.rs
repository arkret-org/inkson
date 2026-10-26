//! Explicit controller confirmation, using original accepted membership and
//! exact grant currents through the authenticated own Station.
use arkret_sdk::exact_current_state::{
    CapabilityGrantExactCurrentSelector, CapabilityGrantExactCurrentSelectorKind,
    CurrentCapabilityGrant, ExactCurrentState, ExactCurrentStateReadRequestBody,
    ExactCurrentStateReadResponseBody, ExactCurrentStateSelector,
};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct JoinBasis {
    controller: arkret_sdk::AccountId,
    agent: arkret_sdk::AccountId,
    controller_join: arkret_sdk::EventId,
    agent_join: arkret_sdk::EventId,
}

#[derive(Clone, Debug)]
struct AuthorityView {
    basis: Option<JoinBasis>,
    strands: Vec<arkret_sdk::StrandView>,
    grants: Vec<CurrentCapabilityGrant>,
    effective: Vec<String>,
    join_status: String,
    management_rules: Vec<String>,
}

fn decision_label(outcome: &arkret_sdk::AuthorizationCheckResponseBody) -> &'static str {
    if matches!(
        outcome.freshness_state,
        Some(arkret_sdk::FreshnessState::Stale | arkret_sdk::FreshnessState::Unknown)
    ) || matches!(
        outcome.authority_status,
        Some(
            arkret_sdk::AuthorityStatus::Lagging
                | arkret_sdk::AuthorityStatus::Unreachable
                | arkret_sdk::AuthorityStatus::Unknown
        )
    ) {
        return "当前证据未确认（不代表允许）";
    }
    let current_precheck = outcome.freshness_state == Some(arkret_sdk::FreshnessState::Fresh)
        && outcome.authority_status == Some(arkret_sdk::AuthorityStatus::Fresh)
        && outcome.policy_evaluations.iter().any(|row| {
            row.get("reason_detail").and_then(Value::as_str)
                == Some("owned_agent_current_capability_and_management")
        });
    if current_precheck {
        return match outcome.decision {
            arkret_sdk::AuthorizationDecision::Allow => "当前权限/管理预检允许（运行时仍需验收）",
            arkret_sdk::AuthorizationDecision::SoftDeny
            | arkret_sdk::AuthorizationDecision::HardDeny => "当前权限/管理预检拒绝",
            arkret_sdk::AuthorizationDecision::Quarantine => "当前权限/管理预检隔离",
            arkret_sdk::AuthorizationDecision::RequireReview => "当前权限/管理预检需批准",
        };
    }
    match outcome.decision {
        arkret_sdk::AuthorizationDecision::Allow => "基础权限允许；完整动态判定未确认",
        arkret_sdk::AuthorizationDecision::SoftDeny
        | arkret_sdk::AuthorizationDecision::HardDeny => "基础权限拒绝；完整动态判定未确认",
        arkret_sdk::AuthorizationDecision::Quarantine => "基础权限隔离；完整动态判定未确认",
        arkret_sdk::AuthorizationDecision::RequireReview => "基础权限需批准；完整动态判定未确认",
    }
}

fn session_matches(
    context: &InksonContext,
    controller: &arkret_sdk::AccountId,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        context.active_account.get().as_ref().map(|a| &a.authority) == Some(controller),
        "Account changed; refresh before confirming Agent authority"
    );
    Ok(())
}

async fn join_original(
    submitter: &crate::event_submit::EventSubmitter,
    realm: &arkret_sdk::RealmId,
    member: &arkret_sdk::ActorId,
    snapshot: &arkret_sdk::RealmStateSnapshot,
) -> anyhow::Result<arkret_sdk::Event> {
    let revision = snapshot
        .parent_membership_revision(member)
        .ok_or_else(|| anyhow::anyhow!("No verified current joined membership"))?;
    let stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let page = submitter
        .scan_stream(&stream, revision.stream_position.checked_sub(1), 1)
        .await?;
    let row = page
        .0
        .committed_events
        .first()
        .ok_or_else(|| anyhow::anyhow!("Accepted membership original is unavailable"))?;
    anyhow::ensure!(
        row.commit().commit_id == revision.commit_id
            && row.commit().stream_position == revision.stream_position
            && row.commit().stream_ref == stream,
        "Membership original differs from current revision"
    );
    let event = row
        .reducer_input()
        .ok_or_else(|| anyhow::anyhow!("Membership original is withheld"))?;
    anyhow::ensure!(
        event.realm_id == *realm,
        "Membership original belongs to another Realm"
    );
    Ok(event.clone())
}

async fn join_basis(
    context: Rc<InksonContext>,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
    agent: &arkret_sdk::AccountId,
    snapshot: &arkret_sdk::RealmStateSnapshot,
) -> anyhow::Result<JoinBasis> {
    session_matches(&context, controller)?;
    // This registered self-resource operation is scoped to verified ownership;
    // a roster display's fallback controller is never authority material.
    let resource = http.agent_get(agent.principal_id.as_str()).await?;
    anyhow::ensure!(
        resource.agent.agent_id == agent.principal_id
            && resource.agent.lifecycle != arkret_sdk::AgentLifecycleState::Deactivated,
        "Agent ownership/lifecycle is unavailable"
    );
    // Since-join members need not read the old create Event. The authenticated
    // complete Snapshot already carries its immutable registered current.
    let genesis_rows: Vec<_> = snapshot
        .current_state_entries
        .iter()
        .filter(|row| {
            matches!(
                row,
                arkret_sdk::CurrentState::Value {
                    selector: arkret_sdk::CurrentSelector::RealmGenesis,
                    ..
                }
            )
        })
        .collect();
    anyhow::ensure!(
        genesis_rows.len() == 1,
        "Realm Genesis current is unavailable"
    );
    let arkret_sdk::CurrentState::Value {
        source_stream_ref,
        revision,
        value,
        ..
    } = genesis_rows[0];
    anyhow::ensure!(
        snapshot.realm_id == *realm
            && *source_stream_ref
                == arkret_sdk::CommitStreamRef::Realm {
                    realm_id: realm.clone()
                }
            && revision.stream_position == 0,
        "Realm Genesis current has another scope or revision"
    );
    let founding: arkret_sdk::RealmGenesis = serde_json::from_value(value.clone())?;
    founding.validate()?;
    anyhow::ensure!(
        founding.purpose == arkret_sdk::RealmPurpose::Collaboration,
        "Owned Agent grants require a Collaboration Realm"
    );
    let submitter = crate::app::runtime_adapter::event_submitter(http.clone());
    anyhow::ensure!(
        submitter.authority()? == controller,
        "Authenticated controller changed"
    );
    let controller_actor = arkret_sdk::ActorId::account(controller.clone());
    let controller_event = join_original(&submitter, realm, &controller_actor, snapshot).await?;
    match controller_event.kind {
        arkret_sdk::EventKind::MemberState => {
            let p: arkret_sdk::MembershipPayload =
                serde_json::from_value(serde_json::to_value(&controller_event.payload)?)?;
            anyhow::ensure!(
                p.member_id == controller_actor
                    && p.membership == arkret_sdk::MembershipPayloadState::Join
                    && p.strand_id.is_none()
                    && p.agent_controller_binding.is_none(),
                "Controller current is not an ordinary join"
            );
        }
        arkret_sdk::EventKind::InviteAccept => anyhow::ensure!(
            controller_event.actor_id == controller_actor,
            "Controller Invite acceptance names another Account"
        ),
        _ => anyhow::bail!("Controller join original is unavailable"),
    }
    let agent_event = join_original(
        &submitter,
        realm,
        &arkret_sdk::ActorId::account(agent.clone()),
        snapshot,
    )
    .await?;
    anyhow::ensure!(
        agent_event.kind == arkret_sdk::EventKind::MemberState
            && agent_event.actor_id == controller_actor,
        "Agent join was not authored by its controller"
    );
    let p: arkret_sdk::MembershipPayload =
        serde_json::from_value(serde_json::to_value(&agent_event.payload)?)?;
    let binding = p
        .agent_controller_binding
        .ok_or_else(|| anyhow::anyhow!("Agent join omits controller binding"))?;
    anyhow::ensure!(
        p.member_id.as_account_id() == Some(agent)
            && p.membership == arkret_sdk::MembershipPayloadState::Join
            && p.strand_id.is_none()
            && binding.controller_account_id == *controller
            && binding.controller_membership_generation_ref == controller_event.event_id
            && binding.controller_terminal_event_ref.is_none(),
        "Agent/controller exact join generations differ"
    );
    session_matches(&context, controller)?;
    Ok(JoinBasis {
        controller: controller.clone(),
        agent: agent.clone(),
        controller_join: controller_event.event_id,
        agent_join: agent_event.event_id,
    })
}

async fn exact_grant(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    grant: &arkret_sdk::GrantId,
) -> anyhow::Result<CurrentCapabilityGrant> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    // Original issuers retain their dedicated withdrawal even after leaving.
    // Public nonce-bound authority acquisition cannot impose a member read gate.
    let before = current_authority(http, realm).await?;
    let request = ExactCurrentStateReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentStateSelector::CapabilityGrant(CapabilityGrantExactCurrentSelector {
            kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
            grant_id: grant.clone(),
        }),
    };
    let result = client
        .exact_current_state(&request, before.current_generation)
        .await?;
    let after = current_authority(http, realm).await?;
    result
        .value()?
        .validate_for_request(&request, before.current_generation)?;
    let head = &before.realm_stream_head;
    anyhow::ensure!(
        before.current_generation == after.current_generation
            && before.current_service_id == after.current_service_id
            && after.realm_stream_head == *head,
        "Grant read crossed a current cut; refresh and confirm again"
    );
    match result.into_value()? {
        ExactCurrentStateReadResponseBody::Present {
            current_state: ExactCurrentState::CapabilityGrant(row),
            effective_stream_head,
            ..
        } => {
            anyhow::ensure!(
                &effective_stream_head == head,
                "Grant result differs from current cut"
            );
            Ok(row)
        }
        _ => anyhow::bail!("Exact accepted Grant current is unavailable"),
    }
}

async fn current_authority(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
) -> anyhow::Result<arkret_sdk::RealmAuthorityBundle> {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| anyhow::anyhow!("authority nonce: {error}"))?;
    let request = arkret_sdk::RealmAuthorityBundleRequestBody {
        realm_id: realm.clone(),
        nonce: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(nonce))
            .map_err(|error| anyhow::anyhow!(error))?,
    };
    let bundle = garth::AuthorityClient::new(http.clone())
        .resolve_authority(&request)
        .await?;
    let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce);
    arkret_identity::verify_realm_authority_bundle(&bundle, &freshness, &keys)?;
    Ok(bundle)
}

async fn retain_accepted_grant_locator(
    context: Rc<InksonContext>,
    submitter: &crate::event_submit::EventSubmitter,
    controller: &arkret_sdk::AccountId,
    accepted: &crate::models::EventSubmissionProgress,
) -> anyhow::Result<()> {
    let commit = accepted
        .commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Accepted grant omits Commit"))?;
    let page = submitter
        .scan_stream(&commit.stream_ref, commit.stream_position.checked_sub(1), 1)
        .await?;
    let row = page
        .0
        .committed_events
        .first()
        .ok_or_else(|| anyhow::anyhow!("Accepted grant original is unavailable"))?;
    anyhow::ensure!(
        row.commit() == commit,
        "Accepted grant locator does not name the original Commit"
    );
    let original = row
        .reducer_input()
        .ok_or_else(|| anyhow::anyhow!("Accepted grant original is withheld"))?;
    anyhow::ensure!(
        original.kind == arkret_sdk::EventKind::CapabilityGrant
            && original.actor_id.as_account_id() == Some(controller),
        "Accepted grant original has another issuer"
    );
    session_matches(&context, controller)?;
    let store = context.state_store.clone();
    let flush = store.write(|state| -> anyhow::Result<_> {
        anyhow::ensure!(
            state.active_authority().as_ref() == Some(controller),
            "Account changed before retaining grant locator"
        );
        // Existing signed-Event raw log; no new cache key, schema or authority
        // projection. The locator is revalidated by exact-current on use.
        state.upsert_raw_operation(
            original.event_id.to_string(),
            Some(original.realm_id.to_string()),
            serde_json::to_value(original)?,
        );
        state.begin_durable_flush()
    })?;
    flush.wait().await?;
    Ok(())
}

/// Locally retained Event ids are discovery hints only. Every button's value
/// and CAS come from an independently read original-issuer exact current.
fn retained_owned_grant_ids(
    context: &InksonContext,
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
) -> Vec<arkret_sdk::GrantId> {
    let state = context.snapshot();
    let mut ids = BTreeSet::new();
    for record in &state.raw_operations {
        if record.realm_id.as_deref() != Some(realm.as_str()) {
            continue;
        }
        let value = record.payload.get("event").unwrap_or(&record.payload);
        let Ok(event) = serde_json::from_value::<arkret_sdk::Event>(value.clone()) else {
            continue;
        };
        if event.kind != arkret_sdk::EventKind::CapabilityGrant
            || event.realm_id != *realm
            || event.actor_id.as_account_id() != Some(controller)
        {
            continue;
        }
        let Ok(payload) = serde_json::to_value(&event.payload)
            .and_then(serde_json::from_value::<arkret_sdk::CapabilityGrantPayload>)
        else {
            continue;
        };
        if matches!(payload.grant.issuer_authority_refs.as_slice(), [arkret_sdk::IssuerAuthorityRef::OwnedAgent { controller_account_id, realm_id, .. }] if controller_account_id == controller && realm_id == realm)
        {
            ids.insert(arkret_sdk::GrantId::from_event_id(&event.event_id));
        }
    }
    ids.into_iter().collect()
}

async fn withdraw_owned_grant(
    context: Rc<InksonContext>,
    base: &str,
    credential: String,
    realm: String,
    account: arkret_sdk::AccountId,
    id: arkret_sdk::GrantId,
) -> Result<(), crate::transport::auth::ApiCallError> {
    use crate::transport::auth::{ApiCallError, AuthoringSessionFence, with_authed_sdk_client};

    let fence = AuthoringSessionFence::capture().map_err(ApiCallError::Failed)?;
    let send_realm = realm.clone();
    let send_account = account.clone();
    let send_id = id.clone();
    let send_fence = fence.clone();
    let send_context = context.clone();
    let submitted = with_authed_sdk_client(base, credential.clone(), |http| async move {
        session_matches(&send_context, &send_account)?;
        let realm = arkret_sdk::RealmId::new(send_realm)?;
        let current = exact_grant(&http, &realm, &send_id).await?;
        send_fence.check_session_identity()?;
        let event = ak_ops::capability_revoke_from_owned_current(
            realm.as_str(),
            send_account.principal_id.as_str(),
            &current,
            Some("controller_withdrawal"),
        )?
        .build_sdk_event("inkson")?;
        let accepted = crate::app::runtime_adapter::event_submitter(http)
            .submit_sdk_event(&event)
            .await?;
        anyhow::ensure!(
            accepted.is_committed(),
            "撤回未接纳：{:?}",
            accepted.rejection_reason_code
        );
        Ok(())
    })
    .await;
    fence
        .check_session_identity()
        .map_err(ApiCallError::Failed)?;

    // A lost response or a rotated transport can leave the submission unknown
    // after the Station committed it. The original issuer's exact current is
    // independently readable after leaving; use a fresh provider transport.
    // This confirms the target state, never manufactures an Event receipt or
    // changes the durable submission's outcome, and never signs another Event.
    let revoked = with_authed_sdk_client(base, credential, |http| async move {
        session_matches(&context, &account)?;
        let realm = arkret_sdk::RealmId::new(realm)?;
        let current = exact_grant(&http, &realm, &id).await?;
        session_matches(&context, &account)?;
        anyhow::ensure!(
            current.value.owned_agent_issuer() == Some(&account),
            "Original issuer differs from withdrawal target"
        );
        Ok(current.value.status == arkret_sdk::CapabilityGrantStatus::Revoked)
    })
    .await;
    fence
        .check_session_identity()
        .map_err(ApiCallError::Failed)?;
    match revoked {
        Ok(true) => Ok(()),
        Ok(false) => {
            submitted.and_then(|()| Err(ApiCallError::Failed(anyhow::anyhow!("撤回结果尚未确认"))))
        }
        Err(error) => Err(error),
    }
}

/// Kept outside the currently joined Agent roster: leaving or deactivation
/// must not hide the original issuer's withdrawal surface.
async fn load(
    context: Rc<InksonContext>,
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
    agent: &arkret_sdk::AccountId,
) -> anyhow::Result<AuthorityView> {
    session_matches(&context, controller)?;
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let before = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&before, realm)?;
    let basis = join_basis(
        context.clone(),
        http,
        realm,
        controller,
        agent,
        before.value()?,
    )
    .await;
    let (basis, join_status) = match basis {
        Ok(b) => (Some(b), "当前成员绑定已核对".into()),
        Err(e) => (None, e.to_string()),
    };
    let mut grants = Vec::new();
    let mut effective = Vec::new();
    let mut management_rules = Vec::new();
    for row in &before.value()?.current_state_entries {
        let arkret_sdk::CurrentState::Value {
            selector: arkret_sdk::CurrentSelector::Policy { .. },
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            continue;
        };
        let document: arkret_sdk::PolicySetValue = serde_json::from_value(value.clone())?;
        document.validate()?;
        let arkret_sdk::PolicySetValue::Governance(policy) = document else {
            continue;
        };
        if policy.policy_kind != arkret_sdk::PolicyKind::Agent {
            continue;
        }
        management_rules.push(format!(
            "规则记录 {}；scope {}；默认 {:?}；生效 {:?}；到期 {:?}；接纳版本 {}",
            policy.id,
            serde_json::to_string(source_stream_ref)?,
            policy.default_effect,
            policy.not_before,
            policy.expires_at,
            revision.commit_id
        ));
        for rule in policy.rules {
            let applicable_target = match &rule.agent_target {
                Some(arkret_sdk::AgentPolicyTarget::All {}) => true,
                Some(arkret_sdk::AgentPolicyTarget::Controller {
                    controller_account_id,
                }) => controller_account_id == controller,
                Some(arkret_sdk::AgentPolicyTarget::Agent { agent_account_id }) => {
                    agent_account_id == agent
                }
                None => false,
            };
            if !applicable_target {
                continue;
            }
            management_rules.push(format!(
                "{}：{:?}；操作 {:?}；动作 {:?}；范围 {}",
                rule.rule_id,
                rule.effect,
                rule.agent_operations,
                rule.actions,
                serde_json::to_string(&rule.resources)?
            ));
        }
    }
    for row in &before.value()?.current_state_entries {
        let arkret_sdk::CurrentState::Value {
            selector: arkret_sdk::CurrentSelector::CapabilityGrant { grant_id },
            value,
            ..
        } = row
        else {
            continue;
        };
        let candidate: arkret_sdk::CapabilityGrant = serde_json::from_value(value.clone())?;
        if candidate.owned_agent_issuer() != Some(controller)
            || !matches!(&candidate.subject, arkret_sdk::CapabilitySubject::Actor(actor)
                if actor == &arkret_sdk::ActorId::account(agent.clone()))
        {
            continue;
        }
        let row = exact_grant(http, realm, grant_id).await?;
        if row.value.owned_agent_issuer() != Some(controller)
            || !matches!(&row.value.subject, arkret_sdk::CapabilitySubject::Actor(actor)
                if actor == &arkret_sdk::ActorId::account(agent.clone()))
        {
            continue;
        }
        let mut decisions = Vec::new();
        for action in &row.value.actions {
            for resource in &row.value.resources {
                let result = crate::transport::realm_read::authz_check_request(http,
                    &arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody {
                        actor_id: arkret_sdk::ActorId::account(agent.clone()), action: action.clone(),
                        resource: Some(resource.clone()), context: None,
                    }).await;
                let outcome = match result {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        decisions.push(format!("{}：当前有效性未确认：{}", action, error));
                        continue;
                    }
                };
                let used = row.value.status == arkret_sdk::CapabilityGrantStatus::Active
                    && outcome.matched_grants.iter().any(|matched| {
                        matched.get("grant_id").and_then(Value::as_str)
                            == Some(row.value.id.as_str())
                    });
                decisions.push(format!(
                    "{}：{}；此记录{}",
                    action,
                    decision_label(&outcome),
                    if used {
                        "被本次判定采用"
                    } else {
                        "未被本次判定采用"
                    }
                ));
            }
        }
        effective.push(decisions.join("；"));
        grants.push(row);
    }
    let strands = if basis.is_some() {
        crate::transport::realm_read::list_realm_strands(http, realm.as_str()).await?
    } else {
        Vec::new()
    };
    let after = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&after, realm)?;
    anyhow::ensure!(
        before.session() == after.session()
            && before.value()?.governance_generation == after.value()?.governance_generation
            && before.value()?.visible_stream_heads == after.value()?.visible_stream_heads,
        "Agent authority changed during refresh; refresh again"
    );
    session_matches(&context, controller)?;
    Ok(AuthorityView {
        basis,
        strands,
        grants,
        effective,
        join_status,
        management_rules,
    })
}

#[derive(Clone)]
struct AuthorityEditor {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    realm: String,
    agent: String,
    current: Cage<Option<AuthorityView>>,
    message: Cage<String>,
    pending: Cage<bool>,
    selected: Cage<BTreeSet<String>>,
    strand: Cage<String>,
    refresh: Cage<u64>,
}
impl AuthorityEditor {
    fn grant(&self) {
        if self.pending.get_untracked() {
            return;
        }
        let Some(account) = self
            .context
            .active_account
            .get()
            .map(|value| value.authority)
        else {
            return;
        };
        let Some(visible_basis) = self.current.get().and_then(|value| value.basis) else {
            return;
        };
        let realm = self.realm.clone();
        let agent = self.agent.clone();
        let scope = self.strand.get();
        let actions = self.selected.get().into_iter().collect::<Vec<_>>();
        if scope.is_empty() || actions.is_empty() {
            return;
        }
        let context = self.context.clone();
        let task_context = context.clone();
        let base = context.base_url.get();
        let token = context.token.get();
        let pending = self.pending;
        let message = self.message;
        let refresh = self.refresh;
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        pending.revise(|value| {
            *value = true;
        });
        message.revise(|value| {
            *value = "正在核对成员关系并签发新授权…".into();
        });
        spawn(&owner, async move {
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                    let realm = arkret_sdk::RealmId::new(realm)?;
                    let agent = arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new(agent)?,
                        account.station_id.clone(),
                    );
                    let fresh = load(task_context.clone(), &http, &realm, &account, &agent).await?;
                    let basis = fresh
                        .basis
                        .ok_or_else(|| anyhow::anyhow!(fresh.join_status))?;
                    anyhow::ensure!(
                        basis == visible_basis,
                        "成员绑定已变化；请刷新并重新明确确认，旧选择不会用于新的 join generation"
                    );
                    let scope = arkret_sdk::StrandId::new(scope)?;
                    anyhow::ensure!(
                        fresh.strands.iter().any(|row| row.strand_id == scope),
                        "所选 Strand 已不可达"
                    );
                    session_matches(&task_context, &account)?;
                    let resource = arkret_sdk::WireResourceSelector::strand(realm.clone(), scope);
                    let actions = actions.iter().map(String::as_str).collect::<Vec<_>>();
                    let event = ak_ops::capability_grant_owned_agent(
                        realm.as_str(),
                        account.principal_id.as_str(),
                        &basis.controller,
                        &basis.agent,
                        &basis.controller_join,
                        &basis.agent_join,
                        &actions,
                        resource,
                    )?
                    .build_sdk_event("inkson")?;
                    let submitter = crate::app::runtime_adapter::event_submitter(http.clone());
                    let accepted = submitter.submit_sdk_event(&event).await?;
                    anyhow::ensure!(
                        accepted.is_committed(),
                        "授权未接纳：{:?}",
                        accepted.rejection_reason_code
                    );
                    retain_accepted_grant_locator(
                        task_context.clone(),
                        &submitter,
                        &account,
                        &accepted,
                    )
                    .await?;
                    let id = arkret_sdk::GrantId::from_event_id(&arkret_sdk::EventId::new(
                        accepted.event_id,
                    )?);
                    let row = exact_grant(&http, &realm, &id).await?;
                    anyhow::ensure!(
                        row.value.owned_agent_issuer() == Some(&account)
                            && matches!(&row.value.subject,
     arkret_sdk::CapabilitySubject::Actor(actor)if actor==&arkret_sdk::ActorId::account(agent)),
                        "接纳授权绑定不一致"
                    );
                    Ok(id)
                })
                .await;
            match result {
                Ok(id) => {
                    message.revise(|value| {
                        *value = format!("已接纳新授权 {id}；正在重读当前有效性");
                    });
                    refresh.revise(|value| *value += 1);
                }
                Err(error) => message.revise(|value| {
                    *value = error.display();
                }),
            }
            pending.revise(|value| {
                *value = false;
            });
        });
    }
}
const ACTIONS: &[(&str, &str)] = &[
    (arkret_wire::CapabilityActionId::MESSAGE_CREATE, "发送消息"),
    (arkret_wire::CapabilityActionId::REACTION_ADD, "添加回应"),
    (arkret_wire::CapabilityActionId::REACTION_REMOVE, "移除回应"),
    (
        arkret_wire::CapabilityActionId::MESSAGE_REVISE_OWN,
        "修改自己消息",
    ),
    (
        arkret_wire::CapabilityActionId::MESSAGE_REDACT_OWN,
        "撤回自己消息",
    ),
    (arkret_wire::CapabilityActionId::STRAND_READ, "读取 Strand"),
    (arkret_wire::CapabilityActionId::EVENT_READ, "读取事件"),
    (arkret_wire::CapabilityActionId::OBJECT_READ, "读取对象"),
    (
        arkret_wire::CapabilityActionId::OBJECT_READ_METADATA,
        "读取对象信息",
    ),
    (
        arkret_wire::CapabilityActionId::OBJECT_READ_CONTENT,
        "读取对象内容",
    ),
    (
        arkret_wire::CapabilityActionId::OBJECT_READ_HISTORY,
        "读取对象历史",
    ),
];
pub(super) fn authority(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
    agent: String,
) -> View {
    let state = AuthorityEditor {
        context: context.clone(),
        owner: scope.downgrade(),
        realm: realm.clone(),
        agent: agent.clone(),
        current: scope.cage(None),
        message: scope.cage(String::new()),
        pending: scope.cage(false),
        selected: scope.cage(BTreeSet::new()),
        strand: scope.cage(String::new()),
        refresh: scope.cage(0),
    };
    let refresh = state.refresh;
    let current = state.current;
    let message = state.message;
    let pending = state.pending;
    let load_context = context.clone();
    let load_realm = realm.clone();
    let load_agent = agent.clone();
    let resource = crate::presentation::widgets::resource(scope, move || {
        let _ = refresh.get();
        let _ = load_context.session_generation.get();
        let context = load_context.clone();
        let base = context.base_url.get();
        let token = context.token.get();
        let account = context.active_account.get().map(|value| value.authority);
        let realm = load_realm.clone();
        let agent = load_agent.clone();
        async move {
            let account = account.ok_or_else(|| "账号未连接".to_string())?;
            crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                let realm = arkret_sdk::RealmId::new(realm)?;
                let agent = arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new(agent)?,
                    account.station_id.clone(),
                );
                load(context, &http, &realm, &account, &agent).await
            })
            .await
            .map_err(|error| error.display())
        }
    });
    scope.effect(move || match resource.data.get() {
        Some(Ok(view)) => {
            message.revise(|value| {
                *value = view.join_status.clone();
            });
            current.revise(|value| {
                *value = Some(view);
            });
        }
        Some(Err(error)) => {
            message.revise(|value| {
                *value = error;
            });
            current.revise(|value| {
                *value = None;
            });
        }
        None => current.revise(|value| {
            *value = None;
        }),
    });
    let selected = state.selected;
    let strand = state.strand;
    let _grant = state.clone();
    let editor_context = context.clone();
    let editor_state = state.clone();
    let editor = reactive(current, move |scope, current| {
        let Some(current) = current else {
            return empty();
        };
        let context = editor_context.clone();
        let state = editor_state.clone();
        let mut children = vec![card(
            scope,
            context.clone(),
            "当前返回的 Agent 治理规则",
            current
                .management_rules
                .into_iter()
                .map(|value| paragraph("", value))
                .collect(),
        )];
        if current.basis.is_some() {
            let enabled = scope.bond(move || !pending.get());
            let options = current
                .strands
                .into_iter()
                .map(|row| {
                    (
                        row.strand_id.to_string(),
                        format!(
                            "{} ({})",
                            row.title.unwrap_or_else(|| row.strand_id.to_string()),
                            row.strand_id
                        ),
                    )
                })
                .collect();
            children.push(choice(
                scope,
                context.clone(),
                "owned-agent-scope",
                "实际范围：仅所选 Strand",
                strand,
                options,
                enabled,
                move |next| {
                    strand.revise(|value| {
                        *value = next;
                    })
                },
            ));
            let mut choices = Vec::new();
            for (action, label) in ACTIONS.iter().copied() {
                let checked = scope.bond(move || selected.get().contains(action));
                choices.push(toggle(
                    scope,
                    context.clone(),
                    &format!("owned-action-{}", choices.len()),
                    label,
                    checked,
                    enabled,
                    move |checked| {
                        selected.revise(|values| {
                            if checked {
                                values.insert(action.to_owned());
                            } else {
                                values.remove(action);
                            }
                        })
                    },
                ));
            }
            children.push(stack("owned-agent-action-selection", choices));
            children.push(scope_preview(
                scope,
                context.clone(),
                state.realm.clone(),
                state.agent.clone(),
                strand,
                selected,
            ));
            let grant = state.clone();
            children.push(paragraph("muted","此次确认只签发上述动作和范围；群模式与参与偏好分别设置。当前管理限制及主人的权限在接纳和后续执行时重新检查。"));
            children.push(action(
                scope,
                context.clone(),
                "owned-agent-confirm-authority",
                "确认签发新的授权",
                "primary",
                scope.bond(move || {
                    !pending.get() && !selected.get().is_empty() && !strand.get().is_empty()
                }),
                move || grant.grant(),
            ));
        }
        for (row, effective) in current.grants.into_iter().zip(current.effective) {
            let mut details = vec![
                paragraph(
                    "",
                    format!("已接纳：{}；状态：{:?}", row.value.id, row.value.status),
                ),
                paragraph("", format!("原签动作：{}", row.value.actions.join("、"))),
                paragraph(
                    "",
                    format!(
                        "原签范围：{}",
                        serde_json::to_string(&row.value.resources).unwrap_or_default()
                    ),
                ),
                paragraph("", format!("当前权限与管理预检：{effective}")),
            ];
            if row.value.status == arkret_sdk::CapabilityGrantStatus::Active
                && let Some(account) = row.value.owned_agent_issuer().cloned()
            {
                details.push(withdraw_button(
                    scope,
                    context.clone(),
                    state.realm.clone(),
                    account,
                    row.value.id.clone(),
                    pending,
                    message,
                    refresh,
                    "owned-agent-revoke-authority",
                ));
            }
            children.push(stack("owned-agent-accepted-grant", details));
        }
        stack("member-agent-authority-body", children)
    });
    card(
        scope,
        context.clone(),
        "明确授权自有 Agent",
        vec![
            paragraph("mono", agent),
            status(message),
            action(
                scope,
                context.clone(),
                "owned-agent-authority-refresh",
                "刷新当前权限与管理限制",
                "secondary",
                scope.bond(move || !pending.get()),
                move || refresh.revise(|value| *value += 1),
            ),
            editor,
        ],
    )
}
fn withdraw_button(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
    account: arkret_sdk::AccountId,
    id: arkret_sdk::GrantId,
    pending: Cage<bool>,
    message: Cage<String>,
    refresh: Cage<u64>,
    key: &str,
) -> View {
    let owner = scope.downgrade();
    let task_context = context.clone();
    action(
        scope,
        context,
        key,
        "撤回此授权",
        "destructive",
        scope.bond(move || !pending.get()),
        move || {
            if pending.get_untracked() {
                return;
            }
            let Some(scope) = owner.upgrade() else { return };
            let context = task_context.clone();
            let base = context.base_url.get();
            let token = context.token.get();
            let realm = realm.clone();
            let account = account.clone();
            let id = id.clone();
            pending.revise(|value| {
                *value = true;
            });
            spawn(&scope, async move {
                let result = withdraw_owned_grant(context, &base, token, realm, account, id).await;
                match result {
                    Ok(()) => {
                        message.revise(|value| {
                            *value = "已撤回；再次授权需要重新确认并签发新记录".into();
                        });
                        refresh.revise(|value| *value += 1);
                    }
                    Err(error) => message.revise(|value| {
                        *value = error.display();
                    }),
                }
                pending.revise(|value| {
                    *value = false;
                });
            });
        },
    )
}
pub(super) fn withdrawal(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let refresh = scope.cage(0_u64);
    let pending = scope.cage(false);
    let message = scope.cage(String::new());
    let load_context = context.clone();
    let load_realm = realm.clone();
    let resource = crate::presentation::widgets::resource(scope, move || {
        let _ = refresh.get();
        let _ = load_context.session_generation.get();
        let context = load_context.clone();
        let base = context.base_url.get();
        let token = context.token.get();
        let realm = load_realm.clone();
        async move {
            crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                let account = context
                    .active_account
                    .get()
                    .ok_or_else(|| anyhow::anyhow!("Account session is unavailable"))?
                    .authority;
                let realm = arkret_sdk::RealmId::new(realm)?;
                let mut values = Vec::new();
                for id in retained_owned_grant_ids(&context, &realm, &account) {
                    let current = exact_grant(&http, &realm, &id).await?;
                    anyhow::ensure!(
                        current.value.owned_agent_issuer() == Some(&account),
                        "Original issuer differs from retained locator"
                    );
                    values.push(current);
                }
                session_matches(&context, &account)?;
                Ok(values)
            })
            .await
            .map_err(|error| error.display())
        }
    });
    let render_context = context.clone();
    let rows = crate::presentation::widgets::resource_content(
        context.clone(),
        format!("owned-withdrawal-{realm}"),
        resource,
        "recovery.panel.loading",
        move |scope, rows| {
            let context = render_context.clone();
            let mut children = Vec::new();
            for row in rows {
                let mut details = vec![
                    paragraph("", format!("{}；{:?}", row.value.id, row.value.status)),
                    paragraph(
                        "",
                        format!(
                            "Agent 完整身份：{}",
                            serde_json::to_string(&row.value.subject).unwrap_or_default()
                        ),
                    ),
                ];
                if row.value.status == arkret_sdk::CapabilityGrantStatus::Active
                    && let Some(account) = row.value.owned_agent_issuer().cloned()
                {
                    details.push(withdraw_button(
                        scope,
                        context.clone(),
                        realm.clone(),
                        account,
                        row.value.id.clone(),
                        pending,
                        message,
                        refresh,
                        "owned-agent-withdraw-retained",
                    ));
                }
                children.push(stack("event", details));
            }
            stack("owned-agent-withdrawal-ledger", children)
        },
    );
    card(
        scope,
        context.clone(),
        "我签发的自有 Agent 授权（离群或停用后仍可撤回）",
        vec![
            action(
                scope,
                context.clone(),
                "owned-agent-withdrawal-refresh",
                "重读原授权记录",
                "secondary",
                scope.bond(move || !pending.get()),
                move || refresh.revise(|value| *value += 1),
            ),
            status(message),
            rows,
        ],
    )
}
fn scope_preview(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
    agent: String,
    strand: Cage<String>,
    selected: Cage<BTreeSet<String>>,
) -> View {
    let load_context = context.clone();
    let resource = crate::presentation::widgets::resource(scope, move || {
        let strand = strand.get();
        let actions = selected.get();
        let context = load_context.clone();
        let realm = realm.clone();
        let agent = agent.clone();
        let base = context.base_url.get();
        let token = context.token.get();
        let _ = context.session_generation.get();
        async move {
            if strand.is_empty() || actions.is_empty() {
                return Ok(String::new());
            }
            crate::transport::auth::with_authed_sdk_client(&base,token,|http|async move{
    let controller=context.active_account.get().ok_or_else(||anyhow::anyhow!("Account session is unavailable"))?.authority;
    let agent=arkret_sdk::AccountId::new(arkret_sdk::DidCoreId::new(agent)?,controller.station_id.clone());
    let scope=arkret_sdk::WireResourceSelector::strand(arkret_sdk::RealmId::new(realm)?,arkret_sdk::StrandId::new(strand)?);
    let mut messages=Vec::new();
    for action in actions{
     let request=|account|arkret_models_collaboration::governance::authorization::AuthorizationCheckRequestBody{
      actor_id:arkret_sdk::ActorId::account(account),action:action.clone(),resource:Some(scope.clone()),context:None,
     };
     let owner=crate::transport::realm_read::authz_check_request(&http,&request(controller.clone())).await?;
     let agent=crate::transport::realm_read::authz_check_request(&http,&request(agent.clone())).await;
     let target=match agent{Ok(outcome)=>decision_label(&outcome).to_owned(),Err(error)=>format!("当前有效性未确认：{error}")};
     messages.push(format!("{}：主人{}；Agent{}",action,decision_label(&owner),target));
    }
    session_matches(&context,&controller)?;Ok(messages.join("；"))
   }).await.map_err(|error|error.display())
        }
    });
    crate::presentation::widgets::resource_content(
        context,
        "owned-agent-current-scope-preview",
        resource,
        "recovery.panel.loading",
        |_, summary| paragraph("muted", summary),
    )
}
