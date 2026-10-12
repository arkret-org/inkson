//! Normal Realm administration of an exact Agent management Policy.
use arkret_models_collaboration::governance::operation_wire::{
    Policy, PolicySetStatePayload, PolicySetValue,
};
use arkret_sdk::exact_current_results::{
    ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
    ExactCurrentResultsReadRequestBody, PolicyExactCurrentSelector, PolicyExactCurrentSelectorKind,
};
use arkret_sdk::{AccountId, CommitStreamRef, CurrentRevision, PolicyId, RealmId, ScopeRef};
use dioxus::prelude::*;

mod model;
use model::{Draft, ResourceDraft, RuleDraft, supported_by_current_backend};

#[derive(Clone)]
struct LoadedPolicy {
    account: AccountId,
    session_generation: u64,
    realm: RealmId,
    id: PolicyId,
    policy: Option<Policy>,
    revision: Option<CurrentRevision>,
    scope: ScopeRef,
}
fn check_session(account: &AccountId, generation: u64) -> anyhow::Result<()> {
    let context = crate::app::SessionContext::get();
    anyhow::ensure!(
        (context.session_generation)() == generation
            && context.active_account().as_ref().map(|a| &a.authority) == Some(account),
        "The Account or Device session changed; read current again"
    );
    Ok(())
}
async fn read_policy(
    http: &arkret_sdk::http_client::Client,
    realm: &RealmId,
    id: &PolicyId,
) -> anyhow::Result<LoadedPolicy> {
    let context = crate::app::SessionContext::get();
    let generation = (context.session_generation)();
    let account = context
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("No active Account"))?
        .authority;
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let before = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&before, realm)?;
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentResultSelector::Policy(PolicyExactCurrentSelector {
            kind: PolicyExactCurrentSelectorKind::Policy,
            policy_id: id.clone(),
        }),
    };
    let result = client
        .exact_current_result(&request, before.value()?.governance_generation)
        .await?;
    let after = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&after, realm)?;
    result
        .value()?
        .validate_for_request(&request, before.value()?.governance_generation)?;
    let (result_head, result_generation) = match result.value()? {
        ExactCurrentResultsReadOutcome::Present {
            effective_stream_head,
            governance_generation,
            ..
        }
        | ExactCurrentResultsReadOutcome::NeverWritten {
            effective_stream_head,
            governance_generation,
            ..
        } => (effective_stream_head, *governance_generation),
    };
    anyhow::ensure!(
        before.session() == after.session()
            && before.value()?.governance_generation == result_generation
            && after.value()?.governance_generation == result_generation
            && before
                .value()?
                .visible_stream_heads
                .iter()
                .find(|h| h.stream_ref == result_head.stream_ref)
                == Some(result_head)
            && after
                .value()?
                .visible_stream_heads
                .iter()
                .find(|h| h.stream_ref == result_head.stream_ref)
                == Some(result_head),
        "The Policy read crossed a governance cut; read current again"
    );
    check_session(&account, generation)?;
    let (policy, revision, scope) = match result.into_value()? {
        ExactCurrentResultsReadOutcome::NeverWritten { .. } => (
            None,
            None,
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
        ),
        ExactCurrentResultsReadOutcome::Present {
            entry: ExactCurrentResultEntry::Policy(row),
            ..
        } => {
            let PolicySetValue::Governance(policy) = row.value.value else {
                anyhow::bail!("This Policy id belongs to another policy family")
            };
            anyhow::ensure!(
                policy.policy_kind == arkret_sdk::PolicyKind::Agent
                    && policy.id == *id
                    && policy.realm_id.as_ref() == Some(realm),
                "The exact result is not this Realm's Agent Policy"
            );
            let scope = match row.source_stream_ref {
                CommitStreamRef::Realm { realm_id } => ScopeRef::Realm { realm_id },
                CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => ScopeRef::Circle {
                    realm_id,
                    circle_id,
                },
                _ => anyhow::bail!("This Policy has an unsupported source scope"),
            };
            (Some(*policy), Some(row.revision), scope)
        }
        _ => anyhow::bail!("The exact result is not a Policy; absence is not established"),
    };
    Ok(LoadedPolicy {
        account,
        session_generation: generation,
        realm: realm.clone(),
        id: id.clone(),
        policy,
        revision,
        scope,
    })
}
fn prepare_write(
    form: &Draft,
    current: &LoadedPolicy,
) -> anyhow::Result<(PolicySetStatePayload, ScopeRef)> {
    check_session(&current.account, current.session_generation)?;
    anyhow::ensure!(
        form.policy_id.trim() == current.id.as_str(),
        "Policy id changed; read the exact id first"
    );
    let scope = form.scope(&current.realm)?;
    ensure_editor_scope(current.policy.is_some(), &current.scope, &scope)?;
    let payload = form.build(
        &current.realm,
        &current.account,
        current.policy.as_ref(),
        current.revision.clone(),
    )?;
    anyhow::ensure!(
        supported_by_current_backend(&payload, &scope),
        "This configuration is not enabled by the current Station admission matrix"
    );
    Ok((payload, scope))
}

fn ensure_editor_scope(
    present: bool,
    original: &ScopeRef,
    requested: &ScopeRef,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !present || original == requested,
        "This editor preserves the accepted source scope; scope migration is not enabled here"
    );
    Ok(())
}

#[component]
pub(super) fn AgentPolicyEditor(realm_id: String, token: Signal<String>) -> Element {
    let mut form = use_signal(Draft::default);
    let mut loaded = use_signal(|| None::<LoadedPolicy>);
    let mut pending = use_signal(|| false);
    let mut awaiting = use_signal(|| None::<PendingPolicyWrite>);
    let mut message = use_signal(|| {
        "Read an exact Policy id before saving. Hidden or unavailable results do not prove absence."
            .to_owned()
    });
    let realm_for_effect = realm_id.clone();
    let context = crate::app::SessionContext::get();
    use_effect(move || {
        let _ = &realm_for_effect;
        let _ = (context.session_generation)();
        loaded.set(None);
        awaiting.set(None);
        pending.set(false);
        message.set("Read current for this Realm and Account before saving.".into());
    });
    let support = loaded
        .read()
        .as_ref()
        .and_then(|current| {
            form.read()
                .build(
                    &current.realm,
                    &current.account,
                    current.policy.as_ref(),
                    current.revision.clone(),
                )
                .ok()
                .and_then(|p| {
                    form.read().scope(&current.realm).ok().map(|s| {
                        supported_by_current_backend(&p, &s)
                            && ensure_editor_scope(current.policy.is_some(), &current.scope, &s)
                                .is_ok()
                    })
                })
        })
        .unwrap_or(false);
    rsx! {
        section { class: "event", "data-testid": "agent-policy-editor",
            h3 { "Agent management Policy" }
            p { "Management limits are separate from Realm joining, member consent and Agent capability grants. A controller selector applies to that complete Account's current and future Agents." }
            fieldset { disabled: pending(),
                TextField { label: "Exact Policy id", value: form.read().policy_id.clone(), onvalue: move |v| { form.write().policy_id = v; loaded.set(None); } }
                button { "data-testid": "agent-policy-read-current", onclick: {
                    let realm = realm_id.clone();
                    move |_| {
                        let context = crate::app::SessionContext::get();
                        let Some(account) = context.active_account().map(|a| a.authority) else { return };
                        let generation = (context.session_generation)();
                        let realm = realm.clone(); let id = form.read().policy_id.clone(); pending.set(true); loaded.set(None);
                        spawn(async move {
                            let base = crate::app::SessionContext::base_url_string();
                            let read_account = account.clone();
                            let result = crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                                check_session(&read_account, generation)?;
                                read_policy(&http, &RealmId::new(realm)?, &PolicyId::new(id.trim())?).await
                            }).await;
                            if check_session(&account, generation).is_err() { return; }
                            match result {
                                Ok(current) => {
                                    if let Some(policy) = &current.policy {
                                        match Draft::from_policy(policy, &current.scope) {
                                            Ok(draft) => form.set(draft),
                                            Err(error) => { message.set(error.to_string()); pending.set(false); return; }
                                        }
                                        message.set(format!("Accepted current {} at {}. Editing does not change the accepted value.", current.id, current.revision.as_ref().unwrap().commit_id));
                                    } else { message.set("Authoritative never_written: this exact id can be created with null expected_revision.".into()); }
                                    loaded.set(Some(current));
                                }
                                Err(error) => message.set(format!("Current is unavailable or hidden; creation remains blocked: {}", error.display())),
                            }
                            pending.set(false);
                        });
                    }
                }, "Read current" }
                TextField { label: "Scope Circle id (blank means this Realm)", value: form.read().circle.clone(), onvalue: move |v| form.write().circle = v }
                Choice { label: "Default effect", value: form.read().default_effect.clone(), options: effects(), onvalue: move |v| form.write().default_effect = v }
                if form.read().default_effect == "require_review" {
                    OperationChoices { selected: form.read().default_operations.clone(), review_only: true, onvalue: move |v| form.write().default_operations = v }
                    Lines { label: "Default approvers: complete SDK ActorId array", value: form.read().default_approvers.clone(), onvalue: move |v| form.write().default_approvers = v }
                    TextField { label: "Default approval threshold", value: form.read().default_threshold.clone(), onvalue: move |v| form.write().default_threshold = v }
                    TextField { label: "Default approval lifetime seconds (1–86400)", value: form.read().default_max_age.clone(), onvalue: move |v| form.write().default_max_age = v }
                }
                TextField { label: "Policy priority (optional)", value: form.read().priority.clone(), onvalue: move |v| form.write().priority = v }
                TextField { label: "Not before (RFC 3339, optional)", value: form.read().not_before.clone(), onvalue: move |v| form.write().not_before = v }
                TextField { label: "Expires at (RFC 3339, optional)", value: form.read().expires_at.clone(), onvalue: move |v| form.write().expires_at = v }
                for index in 0..form.read().rules.len() {
                    RuleEditor { key: "{index}", form, index }
                }
                button { onclick: move |_| form.write().rules.push(RuleDraft::default()), "Add rule" }
                p { "Realm and Circle policies support the registered Agent operations and allow, deny or quarantine effects. Realm Join and Publish can require review; Circle review is unavailable. Action and resource filters must match the selected operations and registered resources. Saving a policy does not confirm runtime authorization." }
                if awaiting.read().is_some() {
                    p { "A submission is awaiting its exact final outcome. New authoring remains blocked; retry uses the original signed Event and durable queue." }
                    button { "data-testid": "agent-policy-retry-pending", onclick: move |_| {
                        let write = awaiting.read().clone();
                        if let Some(write) = write {
                            submit_pending(write, token, pending, awaiting, loaded, message);
                        }
                    }, "Retry original pending Policy" }
                }
                button { "data-testid": "agent-policy-save", disabled: !support || loaded.read().is_none() || awaiting.read().is_some(), onclick: move |_| {
                    let Some(current) = loaded.read().clone() else { return };
                    let prepared = prepare_write(&form.read(), &current);
                    let (payload, scope) = match prepared { Ok(v) => v, Err(e) => { message.set(e.to_string()); return } };
                    let operation = crate::operation::TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::PolicySet>(
                        current.realm.as_str(), current.account.principal_id.as_str(), current.account.station_id.clone(), payload.clone())
                        .effective_scope(scope.clone()).build_sdk_event("inkson");
                    let operation = match operation { Ok(v) => v, Err(e) => { message.set(e.to_string()); return } };
                    let write = PendingPolicyWrite { current, payload, scope, operation, signed: None };
                    awaiting.set(Some(write.clone()));
                    submit_pending(write, token, pending, awaiting, loaded, message);
                }, "Save Agent Policy" }
            }
            p { "data-testid": "agent-policy-status", "{message}" }
        }
    }
}
#[derive(Clone)]
struct PendingPolicyWrite {
    current: LoadedPolicy,
    payload: PolicySetStatePayload,
    scope: ScopeRef,
    operation: crate::operation::LocalOperation,
    signed: Option<arkret_sdk::AuthoredEvent>,
}

async fn author_policy_once<F, Fut>(
    signed: &mut Option<arkret_sdk::AuthoredEvent>,
    author: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<arkret_sdk::AuthoredEvent>>,
{
    if signed.is_none() {
        *signed = Some(author().await?);
    }
    Ok(())
}

fn submit_pending(
    mut write: PendingPolicyWrite,
    token: Signal<String>,
    mut busy: Signal<bool>,
    mut awaiting: Signal<Option<PendingPolicyWrite>>,
    mut loaded: Signal<Option<LoadedPolicy>>,
    mut message: Signal<String>,
) {
    busy.set(true);
    let original_account = write.current.account.clone();
    let original_generation = write.current.session_generation;
    spawn(async move {
        let base = crate::app::SessionContext::base_url_string();
        let result =
            crate::transport::auth::with_authed_sdk_client(&base, token(), |http| async move {
                check_session(&write.current.account, write.current.session_generation)?;
                let submitter =
                    crate::event_submit::EventSubmitter::from_current_session(http.clone());
                if write.signed.is_none() {
                    // No queue/network submission exists before this one-shot authoring completes.
                    awaiting.set(None);
                    author_policy_once(&mut write.signed, || {
                        submitter.author_for_direct_submission(&write.operation)
                    })
                    .await?;
                    check_session(&write.current.account, write.current.session_generation)?;
                    // Freeze the proof as well as the Event identity before any network submission.
                    awaiting.set(Some(write.clone()));
                }
                let accepted = submitter
                    .submit_signed_sdk_events_in_order(std::slice::from_ref(
                        write.signed.as_ref().unwrap(),
                    ))
                    .await;
                check_session(&write.current.account, write.current.session_generation)?;
                let accepted = match accepted {
                    Ok(mut results) => results
                        .pop()
                        .ok_or_else(|| anyhow::anyhow!("Submission omits its final result"))?,
                    Err(error)
                        if crate::ephemeral::authority_rejection_reason(&error).is_some() =>
                    {
                        awaiting.set(None);
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                anyhow::ensure!(
                    accepted.is_committed(),
                    "The original Policy is still pending"
                );
                awaiting.set(None);
                let reread = read_policy(&http, &write.current.realm, &write.current.id).await?;
                check_session(&write.current.account, write.current.session_generation)?;
                let commit = accepted
                    .commit
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Committed Policy omits its Commit"))?;
                anyhow::ensure!(
                    reread
                        .revision
                        .as_ref()
                        .is_some_and(|r| r.commit_id == commit.commit_id
                            && r.stream_position == commit.stream_position)
                        && reread.scope == write.scope
                        && serde_json::to_value(reread.policy.as_ref())?
                            == serde_json::to_value(match &write.payload.value {
                                PolicySetValue::Governance(p) => Some(p),
                                _ => None,
                            })?,
                    "The exact current does not yet confirm this accepted Policy"
                );
                Ok(Some(reread))
            })
            .await;
        if check_session(&original_account, original_generation).is_err() {
            return;
        }
        match result {
            Ok(Some(current)) => {
                loaded.set(Some(current));
                awaiting.set(None);
                message.set("Policy committed and exact current confirmed. Business actions still require their own current checks.".into());
            }
            Ok(None) => {
                loaded.set(None);
                awaiting.set(None);
                message.set("The original Policy was rejected. Read current and confirm a new edit; no automatic overwrite occurred.".into());
            }
            Err(error) => {
                loaded.set(None);
                let state = if awaiting.read().is_some() {
                    "Final outcome remains unknown; new authoring is blocked. Retry the original pending Policy."
                } else {
                    "No pending signed submission remains. Read exact current before editing again; success has not been confirmed."
                };
                message.set(format!("{} {}", state, error.display()));
            }
        }
        busy.set(false);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes() -> (ScopeRef, ScopeRef) {
        let realm_id = RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [11; 32],
        ));
        let circle_id = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [14; 32],
        ));
        (
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            ScopeRef::Circle {
                realm_id,
                circle_id,
            },
        )
    }

    fn signed_policy() -> arkret_sdk::AuthoredEvent {
        let (scope, _) = scopes();
        let ScopeRef::Realm { realm_id } = &scope else {
            unreachable!()
        };
        let account = AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:admin.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:home.example").unwrap(),
        );
        let payload = Draft::default()
            .build(realm_id, &account, None, None)
            .unwrap();
        let operation = crate::operation::TypedOperationBuilder::new_for_station::<
            arkret_sdk::event_spec::PolicySet,
        >(
            realm_id.as_str(),
            account.principal_id.as_str(),
            account.station_id.clone(),
            payload,
        )
        .effective_scope(scope)
        .build_sdk_event("inkson")
        .unwrap();
        let mut event = operation
            .intent()
            .clone()
            .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        crate::event_signer::build_ed25519_device_signer(
            [73; 32],
            "did:web:admin.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
        )
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::ProducerProofContext::new()
                .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
        )
        .unwrap();
        event
    }

    #[test]
    fn present_circle_cannot_be_resaved_as_realm_by_clearing_form_scope() {
        let (realm, circle) = scopes();
        assert!(ensure_editor_scope(true, &circle, &realm).is_err());
        assert!(ensure_editor_scope(true, &circle, &circle).is_ok());
        assert!(ensure_editor_scope(false, &realm, &circle).is_ok());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn pending_retry_preserves_original_proof_and_restored_queue_request() {
        let original = signed_policy();
        let mut retained = None;
        author_policy_once(&mut retained, || async { Ok(original.clone()) })
            .await
            .unwrap();
        let frozen = crate::event_submit::event_submission(retained.as_ref().unwrap()).unwrap();
        let mut queue = garth::SendQueue::default();
        queue
            .enqueue(frozen.clone(), crate::clock::now_utc())
            .unwrap();
        let restored = garth::SendQueue::from_snapshot(
            serde_json::from_value(serde_json::to_value(queue.snapshot()).unwrap()).unwrap(),
        );
        // A retry author would issue a fresh proof; the production gate must never call it.
        author_policy_once(&mut retained, || async {
            anyhow::bail!("retry attempted to re-sign")
        })
        .await
        .unwrap();
        let retry = crate::event_submit::event_submission(retained.as_ref().unwrap()).unwrap();
        assert_eq!(retry.request, frozen.request);
        assert_eq!(restored.items()[0].request(), &retry.request);
        assert_eq!(retained.unwrap(), original);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn failed_initial_authoring_never_creates_a_pending_signed_submission() {
        let mut retained = None;
        assert!(
            author_policy_once(&mut retained, || async {
                anyhow::bail!("pre-authoring failure")
            })
            .await
            .is_err()
        );
        assert!(retained.is_none());
        author_policy_once(&mut retained, || async { Ok(signed_policy()) })
            .await
            .unwrap();
        assert!(retained.is_some());
    }
}

fn effects() -> Vec<String> {
    ["allow", "deny", "quarantine", "require_review"]
        .map(str::to_owned)
        .into()
}
#[component]
fn TextField(label: String, value: String, onvalue: EventHandler<String>) -> Element {
    rsx! { label { "{label}" input { value, oninput: move |e| onvalue.call(e.value()) } } }
}
#[component]
fn Lines(label: String, value: String, onvalue: EventHandler<String>) -> Element {
    rsx! { label { "{label}" textarea { value, oninput: move |e| onvalue.call(e.value()) } } }
}
#[component]
fn Choice(
    label: String,
    value: String,
    options: Vec<String>,
    onvalue: EventHandler<String>,
) -> Element {
    rsx! { label { "{label}" select { value, onchange: move |e| onvalue.call(e.value()), for option in options { option { value: "{option}", "{option}" } } } } }
}
#[component]
fn OperationChoices(
    selected: Vec<String>,
    review_only: bool,
    onvalue: EventHandler<Vec<String>>,
) -> Element {
    let choices = if review_only {
        vec!["join", "publish"]
    } else {
        vec![
            "join",
            "authorize",
            "execute",
            "read",
            "deliver",
            "publish",
            "serve",
        ]
    };
    rsx! { div { for op in choices {
        label { input { r#type: "checkbox", checked: selected.iter().any(|v| v == op), onchange: {
            let selected = selected.clone();
            move |e: Event<FormData>| { let mut values = selected.clone(); values.retain(|v| v != op); if e.checked() { values.push(op.into()); } onvalue.call(values); }
        } } "{op}" }
    } } }
}
#[component]
fn RuleEditor(mut form: Signal<Draft>, index: usize) -> Element {
    let rule = form.read().rules[index].clone();
    rsx! { fieldset { "data-testid": "agent-policy-rule", legend { "Rule {index}" }
        TextField { label: "Stable rule id", value: rule.id, onvalue: move |v| form.write().rules[index].id = v }
        TextField { label: "Rule priority", value: rule.priority, onvalue: move |v| form.write().rules[index].priority = v }
        Choice { label: "Effect", value: rule.effect.clone(), options: effects(), onvalue: move |v| form.write().rules[index].effect = v }
        Choice { label: "Agent selector", value: rule.target.clone(), options: ["all", "controller", "agent"].map(str::to_owned).into(), onvalue: move |v| form.write().rules[index].target = v }
        if rule.target != "all" {
            TextField { label: "Complete Account: principal_id", value: rule.principal, onvalue: move |v| form.write().rules[index].principal = v }
            TextField { label: "Complete Account: station_id", value: rule.station, onvalue: move |v| form.write().rules[index].station = v }
        }
        OperationChoices { selected: rule.operations, review_only: false, onvalue: move |v| form.write().rules[index].operations = v }
        Lines { label: "Registered action ids (optional, whitespace separated)", value: rule.actions, onvalue: move |v| form.write().rules[index].actions = v }
        for resource_index in 0..rule.resources.len() {
            ResourceEditor { form, rule_index: index, resource_index }
        }
        button { onclick: move |_| form.write().rules[index].resources.push(ResourceDraft { kind: "realm".into(), ..ResourceDraft::default() }), "Add resource" }
        if rule.effect == "require_review" {
            Lines { label: "Approvers: complete SDK ActorId array", value: rule.approvers, onvalue: move |v| form.write().rules[index].approvers = v }
            TextField { label: "Approval threshold", value: rule.threshold, onvalue: move |v| form.write().rules[index].threshold = v }
            TextField { label: "Approval lifetime seconds (1–86400)", value: rule.max_age, onvalue: move |v| form.write().rules[index].max_age = v }
        }
        button { onclick: move |_| { form.write().rules.remove(index); }, "Remove rule" }
    } }
}
#[component]
fn ResourceEditor(mut form: Signal<Draft>, rule_index: usize, resource_index: usize) -> Element {
    let resource = form.read().rules[rule_index].resources[resource_index].clone();
    rsx! { div {
        Choice { label: "Resource kind", value: resource.kind, options: ["realm", "strand", "space", "object", "service"].map(str::to_owned).into(), onvalue: move |v| form.write().rules[rule_index].resources[resource_index].kind = v }
        TextField { label: "Resource Realm (optional)", value: resource.realm, onvalue: move |v| form.write().rules[rule_index].resources[resource_index].realm = v }
        TextField { label: "Exact resource reference (optional)", value: resource.reference, onvalue: move |v| form.write().rules[rule_index].resources[resource_index].reference = v }
        button { onclick: move |_| { form.write().rules[rule_index].resources.remove(resource_index); }, "Remove resource" }
    } }
}
