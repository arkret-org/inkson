//! Request, inspect and decide an original management review without committing
//! the candidate before approval. Recovery material exists only in this process.
use arkret_sdk::{ManagementOperation, ManagementReviewDecision, ManagementReviewStatus, RealmId};
use dioxus::prelude::*;
use zeroize::Zeroizing;

use crate::transport::management_review::{
    self as transport, FrozenReview, PreparedDecision, PreparedReview,
};
mod model;

fn drive<F, Fut>(
    token: String,
    mut busy: Signal<bool>,
    mut status: Signal<String>,
    mut loaded: Signal<Option<FrozenReview>>,
    task: F,
) where
    F: FnOnce(arkret_sdk::http_client::Client) -> Fut + 'static,
    Fut: std::future::Future<Output = anyhow::Result<FrozenReview>> + 'static,
{
    if busy() {
        return;
    }
    let context = crate::app::SessionContext::get();
    let generation = (context.session_generation)();
    let Some(account) = context.active_account().map(|v| v.authority) else {
        status.set("请先登录当前 Account".into());
        return;
    };
    busy.set(true);
    status.set("正在核验原请求和当前状态…".into());
    spawn(async move {
        let base = crate::app::SessionContext::base_url_string();
        let result = crate::transport::auth::with_authed_sdk_client(&base, token, task).await;
        // A response from the previous Account/Device must never become this
        // component's selected request, even when its network call completed.
        if transport::check_session(&account, generation).is_err() {
            return;
        }
        match result {
            Ok(review) => {
                status.set(if let Some(commit) = &review.accepted_commit {
                    format!(
                        "原候选业务已提交：{} / {}",
                        commit.event_ref, commit.commit_id
                    )
                } else {
                    format!(
                        "审批状态：{:?}；业务提交须由原 accepted Commit 确认",
                        review.outcome.status
                    )
                });
                loaded.set(Some(review));
            }
            Err(_) => status.set("操作被拒绝或当前证据不可用；保留原请求，刷新后再确认。".into()),
        }
        busy.set(false);
    });
}

#[component]
pub(super) fn ManagementReviewPanel(realm_id: String, token: Signal<String>) -> Element {
    let mut principal = use_signal(String::new);
    let mut station = use_signal(|| {
        crate::app::SessionContext::get()
            .active_account()
            .map(|a| a.authority.station_id.to_string())
            .unwrap_or_default()
    });
    let mut operation = use_signal(|| "join".to_owned());
    let mut loaded = use_signal(|| None::<FrozenReview>);
    let mut retained_request = use_signal(|| None::<PreparedReview>);
    let mut retained_decision = use_signal(|| None::<PreparedDecision>);
    let mut shared = use_signal(String::new);
    let mut recovery = use_signal(|| Zeroizing::new(String::new()));
    let mut root_generation = use_signal(|| "0".to_owned());
    let mut confirmed = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let session = crate::app::SessionContext::get();
    use_effect(move || {
        let _ = (session.session_generation)();
        principal.set(String::new());
        station.set(
            session
                .active_account()
                .map(|v| v.authority.station_id.to_string())
                .unwrap_or_default(),
        );
        loaded.set(None);
        retained_request.set(None);
        retained_decision.set(None);
        shared.set(String::new());
        recovery.set(Zeroizing::new(String::new()));
        root_generation.set("0".into());
        confirmed.set(false);
        busy.set(false);
        status.set("生成原候选或粘贴审批请求。Pending 不改变成员、公开模式或 MLS。".into());
    });
    let unresolved = retained_request().is_some() || retained_decision().is_some();
    let selected = loaded();
    let display = selected.as_ref().and_then(|review| {
        transport::candidate(&review.request)
            .ok()
            .map(|(event, beneficiary)| {
                (
                    event.event_id.to_string(),
                    event.actor_id.to_string(),
                    beneficiary.to_string(),
                    review.outcome.target_digest.to_string(),
                    format!("{:?}", review.outcome.status),
                    review.outcome.expires_at.to_rfc3339(),
                )
            })
    });
    let is_requester = selected.as_ref().is_some_and(|v| {
        v.request.requester_actor_id == arkret_sdk::ActorId::account(v.account.clone())
    });
    let pending = selected
        .as_ref()
        .is_some_and(|v| v.outcome.status == ManagementReviewStatus::Pending);
    let approved = selected.as_ref().is_some_and(|v| {
        matches!(
            v.outcome.status,
            ManagementReviewStatus::Approved | ManagementReviewStatus::Consumed
        )
    });
    let shareable = selected
        .as_ref()
        .and_then(|v| serde_json::to_string_pretty(&v.request).ok())
        .unwrap_or_default();
    rsx! {
        section { class: "event", "data-testid": "management-review-panel",
            h3 { "Agent 管理审批" }
            p { "先冻结真实 controller 签署的候选，请求审批后仍不提交业务。管理员核对原候选，使用身份控制 Recovery Key 批准；最终由原请求者提交同一 Event。" }
            label { "Agent Account: principal_id"
                input { value: "{principal}", disabled: busy() || unresolved, oninput: move |e| { principal.set(e.value()); loaded.set(None); confirmed.set(false); } }
            }
            label { "Agent Account: station_id"
                input { value: "{station}", disabled: busy() || unresolved, oninput: move |e| { station.set(e.value()); loaded.set(None); confirmed.set(false); } }
            }
            label { "原管理意图"
                select { "aria-label": "原管理意图", value: "{operation}", disabled: busy() || unresolved, onchange: move |e| { operation.set(e.value()); loaded.set(None); confirmed.set(false); },
                    option { value: "join", "加入当前 Realm" }
                    option { value: "publish", "公开当前 Realm 的 Agent interaction" }
                }
            }
            button { "data-testid": "management-review-request", disabled: busy() || retained_decision().is_some(), onclick: {
                let realm_id = realm_id.clone();
                move |_| {
                    let parsed = RealmId::new(realm_id.clone()).ok().and_then(|realm| model::agent_account(&principal(), &station()).ok().map(|agent| (realm, agent)));
                    let Some((realm, agent)) = parsed else { status.set("请输入完整有效的 Agent Account。".into()); return; };
                    let op = if operation() == "join" { ManagementOperation::Join } else { ManagementOperation::Publish };
                    confirmed.set(false);
                    let retained = retained_request();
                    drive(token(), busy, status, loaded, move |http| async move {
                        let result = transport::freeze_and_request(&http, realm, agent, op, retained,
                            move |prepared| retained_request.set(Some(prepared))).await?;
                        retained_request.set(None);
                        retained_decision.set(None);
                        Ok(result)
                    });
                }
            }, if retained_request().is_some() { "重试原审批请求（保留原候选）" } else { "冻结候选并请求审批（不提交业务）" } }
            label { "粘贴原审批请求分享内容"
                textarea { "data-testid": "management-review-request-json", value: "{shared}", disabled: busy() || unresolved, oninput: move |e| { shared.set(e.value()); loaded.set(None); confirmed.set(false); } }
            }
            button { "data-testid": "management-review-load", disabled: busy() || unresolved, onclick: {
                let realm_id = realm_id.clone();
                move |_| {
                    let parsed = RealmId::new(realm_id.clone()).ok().and_then(|realm| model::parse_request(&shared(), &realm).ok().map(|request| (realm, request)));
                    let Some((realm, request)) = parsed else { status.set("请粘贴当前 Realm 的完整审批请求。".into()); return; };
                    confirmed.set(false);
                    drive(token(), busy, status, loaded, move |http| async move { transport::load(&http, request, &realm).await });
                }
            }, "读取真实审批状态并核对摘要" }
            if let Some((id, producer, beneficiary, digest, state, expires)) = display {
                dl { "data-testid": "management-review-frozen-candidate",
                    dt { "实际候选 Event" } dd { "{id}" }
                    dt { "原 requester / 实际 producer" } dd { "{producer}" }
                    dt { "Agent beneficiary（完整 Account）" } dd { "{beneficiary}" }
                    dt { "服务端 target_digest" } dd { "{digest}" }
                    dt { "当前状态 / 到期时间" } dd { "{state} / {expires}" }
                }
                details { summary { "分享原审批请求（复制给管理员或原请求者）" }
                    textarea { "data-testid": "management-review-share-json", readonly: true, value: "{shareable}" }
                }
                label { input { r#type: "checkbox", checked: confirmed(), disabled: busy(), onchange: move |e| confirmed.set(e.checked()) }
                    "我已核对当前 Realm、完整 producer、Agent beneficiary 和该 exact Event；批准只针对这些冻结字节。"
                }
                button { "data-testid": "management-review-refresh", disabled: busy(), onclick: {
                    let realm_id = realm_id.clone();
                    move |_| { if let Some(review) = loaded() {
                        let Ok(realm) = RealmId::new(realm_id.clone()) else { return; };
                        confirmed.set(false);
                        drive(token(), busy, status, loaded, move |http| async move { transport::load(&http, review.request, &realm).await });
                    } }
                }, "刷新原请求状态" }
                if let Some(prepared) = retained_decision() {
                    button { "data-testid": "management-review-retry-decision", disabled: busy() || !confirmed(), onclick: move |_| {
                        if let Some(review) = loaded() { let prepared = prepared.clone(); confirmed.set(false); drive(token(), busy, status, loaded, move |http| async move {
                            let outcome = transport::retry_decision(&http, &review, &prepared).await?;
                            retained_decision.set(None);
                            Ok(FrozenReview { outcome, ..review })
                        }); }
                    }, "核对并重试原决定（保留原签署内容）" }
                }
                if pending && !is_requester && retained_decision().is_none() {
                    label { "身份控制 Recovery Key（仅本次签署，不保存）"
                        input { "data-testid": "management-review-recovery-key", r#type: "password", autocomplete: "off", value: recovery.read().as_str(), disabled: busy(), oninput: move |e| recovery.set(Zeroizing::new(e.value())) }
                    }
                    label { "当前身份控制 Root generation"
                        input { r#type: "number", min: "0", value: "{root_generation}", disabled: busy(), oninput: move |e| root_generation.set(e.value()) }
                    }
                    button { "data-testid": "management-review-approve", disabled: busy() || !confirmed(), onclick: move |_| {
                        let Some(review) = loaded() else { return; };
                        let key = std::mem::take(&mut *recovery.write());
                        let Ok(generation) = root_generation().parse::<u64>() else { status.set("Root generation 必须是非负整数。".into()); return; };
                        confirmed.set(false);
                        drive(token(), busy, status, loaded, move |http| async move {
                            let outcome = transport::approve(&http, &review, key, generation, None,
                                move |prepared| retained_decision.set(Some(prepared))).await?;
                            retained_decision.set(None);
                            Ok(FrozenReview { outcome, ..review })
                        });
                    }, "用原生身份控制签名批准该候选" }
                    button { "data-testid": "management-review-reject", disabled: busy() || !confirmed(), onclick: move |_| {
                        if let Some(review) = loaded() { confirmed.set(false); drive(token(), busy, status, loaded, move |http| async move {
                            let outcome = transport::decide_without_approval(&http, &review, ManagementReviewDecision::Reject, None,
                                move |prepared| retained_decision.set(Some(prepared))).await?;
                            retained_decision.set(None);
                            Ok(FrozenReview { outcome, ..review })
                        }); }
                    }, "拒绝原候选" }
                }
                if pending && is_requester && retained_decision().is_none() {
                    button { "data-testid": "management-review-cancel", disabled: busy() || !confirmed(), onclick: move |_| {
                        if let Some(review) = loaded() { confirmed.set(false); drive(token(), busy, status, loaded, move |http| async move {
                            let outcome = transport::decide_without_approval(&http, &review, ManagementReviewDecision::Cancel, None,
                                move |prepared| retained_decision.set(Some(prepared))).await?;
                            retained_decision.set(None);
                            Ok(FrozenReview { outcome, ..review })
                        }); }
                    }, "撤销原请求（不提交业务）" }
                }
                if approved && is_requester && retained_decision().is_none() {
                    button { "data-testid": "management-review-submit", disabled: busy() || !confirmed(), onclick: {
                        let realm_id = realm_id.clone();
                        move |_| { if let Some(review) = loaded() {
                            let Ok(realm) = RealmId::new(realm_id.clone()) else { return; };
                            confirmed.set(false);
                            drive(token(), busy, status, loaded, move |http| async move {
                                let result = transport::submit_approved(&http, &review).await?;
                                anyhow::ensure!(result.is_committed(), "Original reviewed Event is not committed");
                                let mut next = transport::load(&http, review.request, &realm).await?;
                                anyhow::ensure!(next.outcome.status == ManagementReviewStatus::Consumed, "Business commit did not consume the review");
                                next.accepted_commit = result.commit;
                                Ok(next)
                            });
                        } }
                    }, "提交已批准的原候选（结果未知时重试原提交）" }
                }
            }
            p { "data-testid": "management-review-status", "{status}" }
        }
    }
}
