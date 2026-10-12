//! Explicit controller confirmation, using original accepted membership and
//! exact grant currents through the authenticated own Station.
use arkret_sdk::exact_current_results::{
    CapabilityGrantExactCurrentRow, CapabilityGrantExactCurrentSelector,
    CapabilityGrantExactCurrentSelectorKind, ExactCurrentResultEntry, ExactCurrentResultSelector,
    ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
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
    strands: Vec<arkret_sdk::ProjectionStrandRow>,
    grants: Vec<CapabilityGrantExactCurrentRow>,
    effective: Vec<String>,
    join_status: String,
    management_rules: Vec<String>,
}

fn decision_label(outcome: &arkret_sdk::AuthzCheckOutcome) -> &'static str {
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
        && outcome.policy_results.iter().any(|row| {
            row.get("reason_detail").and_then(Value::as_str)
                == Some("owned_agent_current_capability_and_management")
        });
    if current_precheck {
        return match outcome.decision {
            arkret_sdk::AuthzDecision::Allow => "当前权限/管理预检允许（运行时仍需验收）",
            arkret_sdk::AuthzDecision::SoftDeny | arkret_sdk::AuthzDecision::HardDeny => {
                "当前权限/管理预检拒绝"
            }
            arkret_sdk::AuthzDecision::Quarantine => "当前权限/管理预检隔离",
            arkret_sdk::AuthzDecision::RequireReview => "当前权限/管理预检需批准",
        };
    }
    match outcome.decision {
        arkret_sdk::AuthzDecision::Allow => "基础权限允许；完整动态判定未确认",
        arkret_sdk::AuthzDecision::SoftDeny | arkret_sdk::AuthzDecision::HardDeny => {
            "基础权限拒绝；完整动态判定未确认"
        }
        arkret_sdk::AuthzDecision::Quarantine => "基础权限隔离；完整动态判定未确认",
        arkret_sdk::AuthzDecision::RequireReview => "基础权限需批准；完整动态判定未确认",
    }
}

#[component]
fn OwnedAgentScopePreview(
    realm_id: String,
    agent_id: String,
    strand_id: String,
    actions: Vec<String>,
    token: Signal<String>,
) -> Element {
    let mut summary = use_signal(String::new);
    use_effect(move || {
        let realm = realm_id.clone();
        let agent = agent_id.clone();
        let strand = strand_id.clone();
        let actions = actions.clone();
        summary.set("正在读取当前权限和管理判定…".into());
        spawn(async move {
            let base = crate::app::SessionContext::base_url_string();
            let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                let controller = crate::app::SessionContext::get().active_account()
                    .ok_or_else(|| anyhow::anyhow!("Account session is unavailable"))?.authority;
                let agent = arkret_sdk::AccountId::new(arkret_sdk::DidCoreId::new(agent)?, controller.station_id.clone());
                let realm = arkret_sdk::RealmId::new(realm)?;
                let scope = arkret_sdk::WireResourceSelector::strand(realm, arkret_sdk::StrandId::new(strand)?);
                let mut messages = Vec::new();
                for action in actions {
                    let request = |account| arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
                        actor_id: arkret_sdk::ActorId::account(account), action: action.clone(), resource: Some(scope.clone()), context: None,
                    };
                    let owner = crate::transport::realm_read::authz_check_request(&http, &request(controller.clone())).await?;
                    let target = crate::transport::realm_read::authz_check_request(&http, &request(agent.clone())).await;
                    let target = match target {
                        Ok(outcome) => decision_label(&outcome).to_owned(),
                        Err(error) => format!("当前有效性未确认：{}", error.to_string()),
                    };
                    messages.push(format!("{}：主人{}；Agent{}", action, decision_label(&owner), target));
                }
                session_matches(&controller)?;
                Ok(messages.join("；"))
            }).await;
            match result {
                Ok(message) => summary.set(message),
                Err(e) => summary.set(format!("当前证据不可达：{}", e.display())),
            }
        });
    });
    rsx! { p { "data-testid": "owned-agent-current-scope-preview", "{summary}" } }
}

fn session_matches(controller: &arkret_sdk::AccountId) -> anyhow::Result<()> {
    anyhow::ensure!(
        crate::app::SessionContext::get()
            .active_account()
            .as_ref()
            .map(|a| &a.authority)
            == Some(controller),
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
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
    agent: &arkret_sdk::AccountId,
    snapshot: &arkret_sdk::RealmStateSnapshot,
) -> anyhow::Result<JoinBasis> {
    session_matches(controller)?;
    // This registered self-resource operation is scoped to verified ownership;
    // a roster display's fallback controller is never authority material.
    let resource = http.agent_get(agent.principal_id.as_str()).await?;
    anyhow::ensure!(
        resource.agent.agent_id == agent.principal_id
            && resource.agent.lifecycle != arkret_sdk::AgentLifecycleState::Deactivated,
        "Agent ownership/lifecycle is unavailable"
    );
    let genesis = crate::transport::own_station_results::accepted_genesis(http, realm).await?;
    let founding: arkret_sdk::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.event.payload)?)?;
    anyhow::ensure!(
        founding.object.purpose == arkret_sdk::RealmPurpose::Collaboration,
        "Owned Agent grants require a Collaboration Realm"
    );
    let submitter = crate::event_submit::EventSubmitter::from_current_session(http.clone());
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
    session_matches(controller)?;
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
) -> anyhow::Result<CapabilityGrantExactCurrentRow> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    // Original issuers retain their dedicated withdrawal even after leaving.
    // Public nonce-bound authority acquisition cannot impose a member read gate.
    let before = current_authority(http, realm).await?;
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentResultSelector::CapabilityGrant(
            CapabilityGrantExactCurrentSelector {
                kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
                grant_id: grant.clone(),
            },
        ),
    };
    let result = client
        .exact_current_result(&request, before.current_generation)
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
        ExactCurrentResultsReadOutcome::Present {
            entry: ExactCurrentResultEntry::CapabilityGrant(row),
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
    let request = arkret_sdk::AuthorityBundleRequest {
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
    submitter: &crate::event_submit::EventSubmitter,
    controller: &arkret_sdk::AccountId,
    accepted: &crate::models::SubmitEventResult,
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
    session_matches(controller)?;
    let mut store = crate::app::SessionContext::get().state_store;
    let flush = {
        let mut state = store.write();
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
        state.begin_durable_flush()?
    };
    flush.wait().await?;
    Ok(())
}

/// Locally retained Event ids are discovery hints only. Every button's value
/// and CAS come from an independently read original-issuer exact current.
fn retained_owned_grant_ids(
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
) -> Vec<arkret_sdk::GrantId> {
    let state = crate::app::SessionContext::get().state_store.read().load();
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

/// Kept outside the currently joined Agent roster: leaving or deactivation
/// must not hide the original issuer's withdrawal surface.
#[component]
pub(super) fn OwnedAgentWithdrawal(realm_id: String, token: Signal<String>) -> Element {
    let mut rows = use_signal(Vec::<CapabilityGrantExactCurrentRow>::new);
    let mut message = use_signal(String::new);
    let mut pending = use_signal(|| false);
    let mut refresh = use_signal(|| 0_u64);
    let scope = realm_id.clone();
    use_effect(move || {
        let _ = refresh();
        let realm = scope.clone();
        rows.set(Vec::new());
        pending.set(true);
        spawn(async move {
            let base = crate::app::SessionContext::base_url_string();
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                    let account = crate::app::SessionContext::get()
                        .active_account()
                        .ok_or_else(|| anyhow::anyhow!("Account session is unavailable"))?
                        .authority;
                    let realm = arkret_sdk::RealmId::new(realm)?;
                    let mut values = Vec::new();
                    for id in retained_owned_grant_ids(&realm, &account) {
                        let current = exact_grant(&http, &realm, &id).await?;
                        anyhow::ensure!(
                            current.value.owned_agent_issuer() == Some(&account),
                            "Original issuer differs from retained locator"
                        );
                        values.push(current);
                    }
                    session_matches(&account)?;
                    Ok(values)
                })
                .await;
            match result {
                Ok(values) => {
                    rows.set(values);
                    message.set(String::new());
                }
                Err(e) => message.set(e.display()),
            }
            pending.set(false);
        });
    });
    rsx! {
        div { "data-testid": "owned-agent-withdrawal-ledger",
            p { "我签发的自有 Agent 授权（离群或停用后仍可撤回）" }
            p { "{message}" }
            button { r#type: "button", disabled: pending(), onclick: move |_| refresh += 1, "重读原授权记录" }
            for row in rows() {
                div { "data-grant-id": "{row.value.id}",
                    p { "{row.value.id}；{row.value.status:?}" }
                    p { "Agent 完整身份：{serde_json::to_string(&row.value.subject).unwrap_or_default()}" }
                    if row.value.status == arkret_sdk::CapabilityGrantStatus::Active {
                        button { r#type: "button", "data-testid": "owned-agent-withdraw-retained", disabled: pending(),
                            onclick: { let id = row.value.id.clone(); let realm = realm_id.clone(); let account = row.value.owned_agent_issuer().cloned(); move |_| {
                                let Some(account) = account.clone() else { return }; let realm = realm.clone(); let id = id.clone(); pending.set(true);
                                spawn(async move {
                                    let base = crate::app::SessionContext::base_url_string();
                                    let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                                        session_matches(&account)?;
                                        let realm = arkret_sdk::RealmId::new(realm)?;
                                        let current = exact_grant(&http, &realm, &id).await?;
                                        let event = ak_ops::capability_revoke_from_owned_current(realm.as_str(), account.principal_id.as_str(), &current, Some("controller_withdrawal"))?.build_sdk_event("inkson")?;
                                        let accepted = crate::event_submit::EventSubmitter::from_current_session(http.clone()).submit_sdk_event(&event).await?;
                                        anyhow::ensure!(accepted.is_committed(), "撤回未接纳：{:?}", accepted.rejection_reason_code);
                                        anyhow::ensure!(exact_grant(&http, &realm, &id).await?.value.status == arkret_sdk::CapabilityGrantStatus::Revoked, "撤回结果尚未确认");
                                        Ok(())
                                    }).await;
                                    match result { Ok(()) => { message.set("已撤回。旧记录不会恢复；重新授权需明确确认新的记录".into()); refresh += 1; }, Err(e) => message.set(e.display()) }
                                    pending.set(false);
                                });
                            } }, "撤回原授权" }
                    }
                }
            }
        }
    }
}

async fn load(
    http: &arkret_sdk::http_client::Client,
    realm: &arkret_sdk::RealmId,
    controller: &arkret_sdk::AccountId,
    agent: &arkret_sdk::AccountId,
) -> anyhow::Result<AuthorityView> {
    session_matches(controller)?;
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let before = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&before, realm)?;
    let basis = join_basis(http, realm, controller, agent, before.value()?).await;
    let (basis, join_status) = match basis {
        Ok(b) => (Some(b), "当前成员绑定已核对".into()),
        Err(e) => (None, e.to_string()),
    };
    let mut grants = Vec::new();
    let mut effective = Vec::new();
    let mut management_rules = Vec::new();
    for row in &before.value()?.current_state_entries {
        let arkret_sdk::TypedCurrentRow::Value {
            selector: arkret_sdk::CurrentSelector::Policy { .. },
            source_stream_ref,
            revision,
            value,
        } = row
        else {
            continue;
        };
        let state: arkret_sdk::PolicySetStatePayload = serde_json::from_value(value.clone())?;
        state.validate()?;
        let arkret_sdk::PolicySetValue::Governance(policy) = state.value else {
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
        let arkret_sdk::TypedCurrentRow::Value {
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
                    &arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
                        actor_id: arkret_sdk::ActorId::account(agent.clone()), action: action.clone(),
                        resource: Some(resource.clone()), context: None,
                    }).await;
                let outcome = match result {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        decisions.push(format!(
                            "{}：当前有效性未确认：{}",
                            action,
                            error.to_string()
                        ));
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
    session_matches(controller)?;
    Ok(AuthorityView {
        basis,
        strands,
        grants,
        effective,
        join_status,
        management_rules,
    })
}

#[component]
pub(super) fn OwnedAgentAuthority(
    realm_id: String,
    agent_id: String,
    token: Signal<String>,
) -> Element {
    let mut view = use_signal(|| None::<AuthorityView>);
    let mut message = use_signal(String::new);
    let mut pending = use_signal(|| false);
    let mut selected = use_signal(BTreeSet::<String>::new);
    let mut strand = use_signal(String::new);
    let mut refresh = use_signal(|| 0_u64);
    let controller = crate::app::SessionContext::get()
        .active_account()
        .map(|a| a.authority);
    let scope = (realm_id.clone(), agent_id.clone(), controller.clone());
    let expected_scope = scope.clone();
    use_effect(move || {
        let _ = refresh();
        let (realm, agent, account) = scope.clone();
        view.set(None);
        let Some(account) = account else {
            message.set("账号未连接".into());
            return;
        };
        pending.set(true);
        spawn(async move {
            let base = crate::app::SessionContext::base_url_string();
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                    let realm = arkret_sdk::RealmId::new(realm)?;
                    let agent = arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new(agent)?,
                        account.station_id.clone(),
                    );
                    load(&http, &realm, &account, &agent).await
                })
                .await;
            match result {
                Ok(value) => {
                    message.set(value.join_status.clone());
                    view.set(Some(value));
                }
                Err(e) => message.set(e.display()),
            }
            pending.set(false);
        });
    });
    let current = view.read().clone();
    let confirmed = current.as_ref().and_then(|v| v.basis.clone());
    let (realm_for_submit, agent_for_submit, account_for_submit) = expected_scope;
    rsx! {
        div { class: "member-agent-authority", "data-testid": "member-agent-authority",
            p { "明确授权自有 Agent" }
            if let Some(account) = controller {
                p { class: "mono", "主人账号：{account}" }
                p { class: "mono", "Agent principal：{agent_id}；Station：{account.station_id}" }
            }
            p { "{message}" }
            button { r#type: "button", disabled: pending(), onclick: move |_| refresh += 1, "刷新当前权限与管理限制" }
            if let Some(current) = current {
                details {
                    summary { "当前返回的 Agent 治理规则" }
                    p { "规则的当前适用性、父 scope 和最终结果由治理服务核对；未返回记录不代表没有限制。" }
                    for rule in current.management_rules {
                        p { "{rule}" }
                    }
                }
                if confirmed.is_some() {
                    label { "实际范围：仅所选 Strand" }
                    select { "data-testid": "owned-agent-scope", value: "{strand}", disabled: pending(),
                        onchange: move |e| strand.set(e.value()),
                        option { value: "", "选择 Strand" }
                        for row in current.strands {
                            option { value: "{row.strand_id}", "{row.title.clone().unwrap_or_else(|| row.strand_id.to_string())} ({row.strand_id})" }
                        }
                    }
                    for (action, label) in [
                        ("ak.message.create", "发送消息"), ("ak.reaction.add", "添加回应"),
                        ("ak.reaction.remove", "移除回应"), ("ak.message.revise.own", "修改自己消息"),
                        ("ak.message.redact.own", "撤回自己消息"), ("ak.strand.read", "读取 Strand"),
                        ("ak.event.read", "读取事件"), ("ak.object.read", "读取对象"),
                        ("ak.object.read_metadata", "读取对象信息"), ("ak.object.read_content", "读取对象内容"),
                        ("ak.object.read_history", "读取对象历史"),
                    ] {
                        label {
                            input { r#type: "checkbox", checked: selected.read().contains(action), disabled: pending(),
                                onchange: move |e| { selected.with_mut(|set| { if e.checked() { set.insert(action.to_owned()); } else { set.remove(action); } }); } }
                            "{label}"
                        }
                    }
                    p { r#"已选择：{selected.read().iter().cloned().collect::<Vec<_>>().join("、")}；Strand：{strand}"# }
                    if !strand.read().is_empty() && !selected.read().is_empty() {
                        OwnedAgentScopePreview {
                            key: r#"{strand}:{selected.read().iter().cloned().collect::<Vec<_>>().join(",")}"#,
                            realm_id: realm_id.clone(), agent_id: agent_id.clone(), strand_id: strand(),
                            actions: selected.read().iter().cloned().collect(), token,
                        }
                    }
                    p { "此次确认只签发上述动作和范围；群模式与参与偏好分别设置。当前管理限制及主人的权限在接纳和后续执行时重新检查。" }
                    button { r#type: "button", "data-testid": "owned-agent-confirm-authority",
                        disabled: pending() || selected.read().is_empty() || strand.read().is_empty(),
                        onclick: move |_| {
                            let Some(account) = account_for_submit.clone() else { return };
                            let Some(visible_basis) = confirmed.clone() else { return };
                            let realm = realm_for_submit.clone(); let agent = agent_for_submit.clone();
                            let scope = strand(); let actions = selected.read().iter().cloned().collect::<Vec<_>>();
                            pending.set(true); message.set("正在核对成员关系并签发新授权…".into());
                            spawn(async move {
                                let base = crate::app::SessionContext::base_url_string();
                                let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                                    let realm = arkret_sdk::RealmId::new(realm)?;
                                    let agent = arkret_sdk::AccountId::new(arkret_sdk::DidCoreId::new(agent)?, account.station_id.clone());
                                    let fresh = load(&http, &realm, &account, &agent).await?;
                                    let basis = fresh.basis.ok_or_else(|| anyhow::anyhow!(fresh.join_status))?;
                                    anyhow::ensure!(basis == visible_basis,
                                        "成员绑定已变化；请刷新并重新明确确认，旧选择不会用于新的 join generation");
                                    let scope = arkret_sdk::StrandId::new(scope)?;
                                    anyhow::ensure!(fresh.strands.iter().any(|s| s.strand_id == scope), "所选 Strand 已不可达");
                                    session_matches(&account)?;
                                    let resource = arkret_sdk::WireResourceSelector::strand(realm.clone(), scope);
                                    let actions = actions.iter().map(String::as_str).collect::<Vec<_>>();
                                    let event = ak_ops::capability_grant_owned_agent(realm.as_str(), account.principal_id.as_str(),
                                        &basis.controller, &basis.agent, &basis.controller_join, &basis.agent_join, &actions, resource)?.build_sdk_event("inkson")?;
                                    let submitter = crate::event_submit::EventSubmitter::from_current_session(http.clone());
                                    let accepted = submitter.submit_sdk_event(&event).await?;
                                    anyhow::ensure!(accepted.is_committed(), "授权未接纳：{:?}", accepted.rejection_reason_code);
                                    retain_accepted_grant_locator(&submitter, &account, &accepted).await?;
                                    let id = arkret_sdk::GrantId::from_event_id(&arkret_sdk::EventId::new(accepted.event_id)?);
                                    let row = exact_grant(&http, &realm, &id).await?;
                                    anyhow::ensure!(row.value.owned_agent_issuer() == Some(&account)
                                        && matches!(&row.value.subject, arkret_sdk::CapabilitySubject::Actor(actor) if actor == &arkret_sdk::ActorId::account(agent)), "接纳授权绑定不一致");
                                    Ok(id)
                                }).await;
                                match result { Ok(id) => { message.set(format!("已接纳新授权 {id}；正在重读当前有效性")); refresh += 1; }, Err(e) => message.set(e.display()) }
                                pending.set(false);
                            });
                        }, "确认签发新的授权" }
                }
                for (row, effective) in current.grants.into_iter().zip(current.effective) {
                    div { "data-testid": "owned-agent-accepted-grant", "data-grant-id": "{row.value.id}",
                        p { "已接纳：{row.value.id}；状态：{row.value.status:?}" }
                        p { r#"原签动作：{row.value.actions.join("、")}"# }
                        p { "原签范围：{serde_json::to_string(&row.value.resources).unwrap_or_default()}" }
                        p { "当前权限与管理预检：{effective}" }
                        if row.value.status == arkret_sdk::CapabilityGrantStatus::Active {
                            button { r#type: "button", "data-testid": "owned-agent-revoke-authority", disabled: pending(),
                                onclick: { let id = row.value.id.clone(); let realm = realm_id.clone(); let account = row.value.owned_agent_issuer().cloned(); move |_| {
                                    let Some(account) = account.clone() else { return };
                                    let id = id.clone(); let realm = realm.clone(); pending.set(true);
                                    spawn(async move {
                                        let base = crate::app::SessionContext::base_url_string();
                                        let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                                            session_matches(&account)?;
                                            let realm = arkret_sdk::RealmId::new(realm)?;
                                            let row = exact_grant(&http, &realm, &id).await?;
                                            let event = ak_ops::capability_revoke_from_owned_current(realm.as_str(), account.principal_id.as_str(), &row, Some("controller_withdrawal"))?.build_sdk_event("inkson")?;
                                            let accepted = crate::event_submit::EventSubmitter::from_current_session(http.clone()).submit_sdk_event(&event).await?;
                                            anyhow::ensure!(accepted.is_committed(), "撤回未接纳：{:?}", accepted.rejection_reason_code);
                                            let current = exact_grant(&http, &realm, &id).await?;
                                            anyhow::ensure!(current.value.status == arkret_sdk::CapabilityGrantStatus::Revoked, "撤回结果尚未确认");
                                            Ok(())
                                        }).await;
                                        match result { Ok(()) => { message.set("已撤回；再次授权需要重新确认并签发新记录".into()); refresh += 1; }, Err(e) => message.set(e.display()) }
                                        pending.set(false);
                                    });
                                } }, "撤回此授权" }
                        }
                    }
                }
            }
        }
    }
}
