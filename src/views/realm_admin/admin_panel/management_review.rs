//! Request, inspect and decide an original management review without committing
//! the candidate before approval. Recovery material exists only in this process.
use std::cell::RefCell;
use std::rc::Rc;

use arkret_sdk::{ManagementOperation, ManagementReviewDecision, ManagementReviewStatus, RealmId};
use glory::{Cage, Scope};
use zeroize::Zeroizing;

use crate::presentation::{InksonContext, View};
use crate::transport::management_review::{
    self as transport, FrozenReview, PreparedDecision, PreparedReview,
};
use crate::views::settings::widgets::*;
mod model;

fn retry_decision_action(
    context: Rc<InksonContext>,
    retained: glory::Bond<bool>,
    enabled: glory::Bond<bool>,
    retry: impl FnMut() + 'static,
) -> View {
    let retry = Rc::new(RefCell::new(retry));
    reactive(retained, move |scope, retained| {
        if !retained {
            return empty();
        }
        let retry = retry.clone();
        action(
            scope,
            context.clone(),
            "management-review-retry-decision",
            "核对并重试原决定（保留原签署内容）",
            "secondary",
            enabled,
            move || (retry.borrow_mut())(),
        )
    })
}

fn fresh_decision_controls(
    state: ReviewPage,
    retained: glory::Bond<bool>,
    enabled: glory::Bond<bool>,
) -> View {
    reactive(retained, move |scope, retained| {
        if retained {
            return empty();
        }
        let context = state.context.clone();
        let recovery = state.recovery;
        let value = scope.bond(move || recovery.get().as_str().to_owned());
        let approve = state.clone();
        let reject = state.clone();
        stack(
            "management-review-new-decision-controls",
            vec![
                Box::new(
                    sapid::field("management-review-recovery-key")
                        .unstyled()
                        .class("field")
                        .label("身份控制 Recovery Key（仅本次签署，不保存）")
                        .control(move |field| {
                            sapid::text_field()
                                .unstyled()
                                .field(field)
                                .purpose(glory::prelude::Purpose::Password)
                                .value(value)
                                .on_value_change(move |next| {
                                    recovery.revise(|value| {
                                        *value = Zeroizing::new(next);
                                    })
                                })
                        }),
                ),
                input(
                    scope,
                    context.clone(),
                    "management-review-root-generation",
                    "当前身份控制 Root generation",
                    state.root_generation,
                    true,
                ),
                action(
                    scope,
                    context.clone(),
                    "management-review-approve",
                    "用原生身份控制签名批准该候选",
                    "primary",
                    enabled,
                    move || approve.approve(),
                ),
                action(
                    scope,
                    context,
                    "management-review-reject",
                    "拒绝原候选",
                    "destructive",
                    enabled,
                    move || reject.reject(),
                ),
            ],
        )
    })
}

fn drive<F, Fut>(
    owner: glory::ui::WeakScope,
    context: Rc<InksonContext>,
    token: String,
    busy: Cage<bool>,
    status: Cage<String>,
    loaded: Cage<Option<FrozenReview>>,
    task: F,
) where
    F: FnOnce(arkret_sdk::http_client::Client) -> Fut + 'static,
    Fut: std::future::Future<Output = anyhow::Result<FrozenReview>> + 'static,
{
    if busy.get() {
        return;
    }
    let generation = context.session_generation.get();
    let Some(account) = context.active_account.get().map(|v| v.authority) else {
        status.revise(|value| {
            *value = "请先登录当前 Account".into();
        });
        return;
    };
    busy.revise(|value| {
        *value = true;
    });
    status.revise(|value| {
        *value = "正在核验原请求和当前状态…".into();
    });
    if let Some(scope) = owner.upgrade() {
        spawn(&scope, async move {
            let base = context.base_url.get();
            let result = crate::transport::auth::with_authed_sdk_client(&base, token, task).await;
            // A response from the previous Account/Device must never become this
            // component's selected request, even when its network call completed.
            if transport::check_session(&account, generation).is_err() {
                return;
            }
            match result {
                Ok(review) => {
                    status.revise(|value| {
                        *value = if let Some(commit) = &review.accepted_commit {
                            format!(
                                "原候选业务已提交：{} / {}",
                                commit.event_ref, commit.commit_id
                            )
                        } else {
                            format!(
                                "审批状态：{:?}；业务提交须由原 accepted Commit 确认",
                                review.outcome.status
                            )
                        };
                    });
                    loaded.revise(|value| {
                        *value = Some(review);
                    });
                }
                Err(_) => status.revise(|value| {
                    *value = "操作被拒绝或当前证据不可用；保留原请求，刷新后再确认。".into();
                }),
            }
            busy.revise(|value| {
                *value = false;
            });
        });
    };
}

#[derive(Clone)]
struct ReviewPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    realm: String,
    principal: Cage<String>,
    station: Cage<String>,
    operation: Cage<String>,
    loaded: Cage<Option<FrozenReview>>,
    retained_request: Cage<Option<PreparedReview>>,
    retained_decision: Cage<Option<PreparedDecision>>,
    shared: Cage<String>,
    recovery: Cage<Zeroizing<String>>,
    root_generation: Cage<String>,
    confirmed: Cage<bool>,
    status: Cage<String>,
    busy: Cage<bool>,
}
impl ReviewPage {
    #[allow(unused_variables)]
    fn request(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let principal = self.principal;
        let station = self.station;
        let operation = self.operation;
        let loaded = self.loaded;
        let retained_request = self.retained_request;
        let retained_decision = self.retained_decision;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = {
            let realm_id = realm_id.clone();
            move |_| {
                let parsed = RealmId::new(realm_id.clone()).ok().and_then(|realm| {
                    model::agent_account(&principal.get(), &station.get())
                        .ok()
                        .map(|agent| (realm, agent))
                });
                let Some((realm, agent)) = parsed else {
                    status.revise(|value| {
                        *value = "请输入完整有效的 Agent Account。".into();
                    });
                    return;
                };
                let op = if operation.get() == "join" {
                    ManagementOperation::Join
                } else {
                    ManagementOperation::Publish
                };
                confirmed.revise(|value| {
                    *value = false;
                });
                let retained = retained_request.get();
                drive(
                    owner.clone(),
                    context.clone(),
                    token.get(),
                    busy,
                    status,
                    loaded,
                    move |http| async move {
                        let result = transport::freeze_and_request(
                            &http,
                            realm,
                            agent,
                            op,
                            retained,
                            move |prepared| {
                                retained_request.revise(|value| {
                                    *value = Some(prepared);
                                })
                            },
                        )
                        .await?;
                        retained_request.revise(|value| {
                            *value = None;
                        });
                        retained_decision.revise(|value| {
                            *value = None;
                        });
                        Ok(result)
                    },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn load(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let shared = self.shared;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = {
            let realm_id = realm_id.clone();
            move |_| {
                let parsed = RealmId::new(realm_id.clone()).ok().and_then(|realm| {
                    model::parse_request(&shared.get(), &realm)
                        .ok()
                        .map(|request| (realm, request))
                });
                let Some((realm, request)) = parsed else {
                    status.revise(|value| {
                        *value = "请粘贴当前 Realm 的完整审批请求。".into();
                    });
                    return;
                };
                confirmed.revise(|value| {
                    *value = false;
                });
                drive(
                    owner.clone(),
                    context.clone(),
                    token.get(),
                    busy,
                    status,
                    loaded,
                    move |http| async move { transport::load(&http, request, &realm).await },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn refresh(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = {
            let realm_id = realm_id.clone();
            move |_| {
                if let Some(review) = loaded.get() {
                    let Ok(realm) = RealmId::new(realm_id.clone()) else {
                        return;
                    };
                    confirmed.revise(|value| {
                        *value = false;
                    });
                    drive(
                        owner.clone(),
                        context.clone(),
                        token.get(),
                        busy,
                        status,
                        loaded,
                        move |http| async move { transport::load(&http, review.request, &realm).await },
                    );
                }
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn retry(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let retained_decision = self.retained_decision;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let Some(prepared) = self.retained_decision.get() else {
            return;
        };
        let action = move |_| {
            if let Some(review) = loaded.get() {
                let prepared = prepared.clone();
                confirmed.revise(|value| {
                    *value = false;
                });
                drive(
                    owner.clone(),
                    context.clone(),
                    token.get(),
                    busy,
                    status,
                    loaded,
                    move |http| async move {
                        let outcome = transport::retry_decision(&http, &review, &prepared).await?;
                        retained_decision.revise(|value| {
                            *value = None;
                        });
                        Ok(FrozenReview { outcome, ..review })
                    },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn approve(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let retained_decision = self.retained_decision;
        let recovery = self.recovery;
        let root_generation = self.root_generation;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = move |_| {
            let Some(review) = loaded.get() else {
                return;
            };
            let mut key = None;
            recovery.revise(|value| key = Some(std::mem::take(value)));
            let key = key.unwrap_or_default();
            let Ok(generation) = root_generation.get().parse::<u64>() else {
                status.revise(|value| {
                    *value = "Root generation 必须是非负整数。".into();
                });
                return;
            };
            confirmed.revise(|value| {
                *value = false;
            });
            drive(
                owner.clone(),
                context.clone(),
                token.get(),
                busy,
                status,
                loaded,
                move |http| async move {
                    let outcome = transport::approve(
                        &http,
                        &review,
                        key,
                        generation,
                        None,
                        move |prepared| {
                            retained_decision.revise(|value| {
                                *value = Some(prepared);
                            })
                        },
                    )
                    .await?;
                    retained_decision.revise(|value| {
                        *value = None;
                    });
                    Ok(FrozenReview { outcome, ..review })
                },
            );
        };
        action(());
    }
    #[allow(unused_variables)]
    fn reject(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let retained_decision = self.retained_decision;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = move |_| {
            if let Some(review) = loaded.get() {
                confirmed.revise(|value| {
                    *value = false;
                });
                drive(
                    owner.clone(),
                    context.clone(),
                    token.get(),
                    busy,
                    status,
                    loaded,
                    move |http| async move {
                        let outcome = transport::decide_without_approval(
                            &http,
                            &review,
                            ManagementReviewDecision::Reject,
                            None,
                            move |prepared| {
                                retained_decision.revise(|value| {
                                    *value = Some(prepared);
                                })
                            },
                        )
                        .await?;
                        retained_decision.revise(|value| {
                            *value = None;
                        });
                        Ok(FrozenReview { outcome, ..review })
                    },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn cancel(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let retained_decision = self.retained_decision;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = move |_| {
            if let Some(review) = loaded.get() {
                confirmed.revise(|value| {
                    *value = false;
                });
                drive(
                    owner.clone(),
                    context.clone(),
                    token.get(),
                    busy,
                    status,
                    loaded,
                    move |http| async move {
                        let outcome = transport::decide_without_approval(
                            &http,
                            &review,
                            ManagementReviewDecision::Cancel,
                            None,
                            move |prepared| {
                                retained_decision.revise(|value| {
                                    *value = Some(prepared);
                                })
                            },
                        )
                        .await?;
                        retained_decision.revise(|value| {
                            *value = None;
                        });
                        Ok(FrozenReview { outcome, ..review })
                    },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn submit(&self) {
        let context = self.context.clone();
        let owner = self.owner.clone();
        let token = context.token;
        let realm_id = self.realm.clone();
        let loaded = self.loaded;
        let confirmed = self.confirmed;
        let status = self.status;
        let busy = self.busy;
        let action = {
            let realm_id = realm_id.clone();
            move |_| {
                if let Some(review) = loaded.get() {
                    let Ok(realm) = RealmId::new(realm_id.clone()) else {
                        return;
                    };
                    confirmed.revise(|value| {
                        *value = false;
                    });
                    drive(
                        owner.clone(),
                        context.clone(),
                        token.get(),
                        busy,
                        status,
                        loaded,
                        move |http| async move {
                            let result = transport::submit_approved(&http, &review).await?;
                            anyhow::ensure!(
                                result.is_committed(),
                                "Original reviewed Event is not committed"
                            );
                            let mut next = transport::load(&http, review.request, &realm).await?;
                            anyhow::ensure!(
                                next.outcome.status == ManagementReviewStatus::Consumed,
                                "Business commit did not consume the review"
                            );
                            next.accepted_commit = result.commit;
                            Ok(next)
                        },
                    );
                }
            }
        };
        action(());
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let station = context
        .active_account
        .get()
        .map(|account| account.authority.station_id.to_string())
        .unwrap_or_default();
    let state = ReviewPage {
        context: context.clone(),
        owner: scope.downgrade(),
        realm,
        principal: scope.cage(String::new()),
        station: scope.cage(station),
        operation: scope.cage("join".into()),
        loaded: scope.cage(None),
        retained_request: scope.cage(None),
        retained_decision: scope.cage(None),
        shared: scope.cage(String::new()),
        recovery: scope.cage(Zeroizing::new(String::new())),
        root_generation: scope.cage("0".into()),
        confirmed: scope.cage(false),
        status: scope.cage("生成原候选或粘贴审批请求。Pending 不改变成员、公开模式或 MLS。".into()),
        busy: scope.cage(false),
    };
    let reset = state.clone();
    scope.effect(move || {
        let _ = reset.context.session_generation.get();
        reset.loaded.revise(|value| {
            *value = None;
        });
        reset.retained_request.revise(|value| {
            *value = None;
        });
        reset.retained_decision.revise(|value| {
            *value = None;
        });
        reset.recovery.revise(|value| {
            *value = Zeroizing::new(String::new());
        });
        reset.confirmed.revise(|value| {
            *value = false;
        });
    });
    let principal = state.principal;
    let station = state.station;
    let operation = state.operation;
    let shared = state.shared;
    let loaded = state.loaded;
    let confirmed = state.confirmed;
    let busy = state.busy;
    let retained = state.retained_request;
    let decision = state.retained_decision;
    let editable =
        scope.bond(move || !busy.get() && retained.get().is_none() && decision.get().is_none());
    let request = state.clone();
    let load = state.clone();
    let details_state = state.clone();
    let details = reactive(loaded, move |scope, review| {
        let Some(review) = review else {
            return empty();
        };
        let context = details_state.context.clone();
        let state = details_state.clone();
        let refresh = state.clone();
        let retry = state.clone();
        let cancel = state.clone();
        let submit = state.clone();
        let is_requester = review.request.requester_actor_id
            == arkret_sdk::ActorId::account(review.account.clone());
        let pending = review.outcome.status == ManagementReviewStatus::Pending;
        let approved = matches!(
            review.outcome.status,
            ManagementReviewStatus::Approved | ManagementReviewStatus::Consumed
        );
        let enabled =
            scope.bond(move || !busy.get() && confirmed.get() && decision.get().is_none());
        let mut children = Vec::new();
        if let Ok((event, beneficiary)) = transport::candidate(&review.request) {
            children.push(line(
                "management-review-frozen-candidate metric-grid",
                vec![
                    card(
                        scope,
                        context.clone(),
                        "实际候选 Event",
                        vec![plain(event.event_id.to_string())],
                    ),
                    card(
                        scope,
                        context.clone(),
                        "原 requester / 实际 producer",
                        vec![plain(event.actor_id.to_string())],
                    ),
                    card(
                        scope,
                        context.clone(),
                        "Agent beneficiary（完整 Account）",
                        vec![plain(beneficiary.to_string())],
                    ),
                    card(
                        scope,
                        context.clone(),
                        "服务端 target_digest",
                        vec![plain(review.outcome.target_digest.to_string())],
                    ),
                    card(
                        scope,
                        context.clone(),
                        "当前状态 / 到期时间",
                        vec![plain(format!(
                            "{:?} / {}",
                            review.outcome.status,
                            review.outcome.expires_at.to_rfc3339()
                        ))],
                    ),
                ],
            ));
        }
        let shareable = serde_json::to_string_pretty(&review.request).unwrap_or_default();
        children.push(Box::new(
            sapid::field("management-review-share-json")
                .unstyled()
                .class("field")
                .label("分享原审批请求（复制给管理员或原请求者）")
                .control(move |field| {
                    sapid::text_field()
                        .unstyled()
                        .field(field)
                        .multiline(true)
                        .readonly(true)
                        .value(shareable.clone())
                }),
        ));
        children.push(toggle(scope,context.clone(),"management-review-confirm","我已核对当前 Realm、完整 producer、Agent beneficiary 和该 exact Event；批准只针对这些冻结字节。",
   confirmed,scope.bond(move||!busy.get()),move|next|confirmed.revise(|value|{*value=next;})));
        children.push(action(
            scope,
            context.clone(),
            "management-review-refresh",
            "刷新原请求状态",
            "secondary",
            scope.bond(move || !busy.get()),
            move || refresh.refresh(),
        ));
        children.push(retry_decision_action(
            context.clone(),
            scope.bond(move || decision.get().is_some()),
            scope.bond(move || !busy.get() && confirmed.get() && decision.get().is_some()),
            move || retry.retry(),
        ));
        if pending && !is_requester {
            children.push(fresh_decision_controls(
                state.clone(),
                scope.bond(move || decision.get().is_some()),
                enabled,
            ));
        }
        if pending && is_requester {
            children.push(action(
                scope,
                context.clone(),
                "management-review-cancel",
                "撤销原请求（不提交业务）",
                "secondary",
                enabled,
                move || cancel.cancel(),
            ));
        }
        if approved && is_requester {
            children.push(action(
                scope,
                context.clone(),
                "management-review-submit",
                "提交已批准的原候选（结果未知时重试原提交）",
                "primary",
                enabled,
                move || submit.submit(),
            ));
        }
        stack("management-review-selected", children)
    });
    card(
        scope,
        context.clone(),
        "Agent 管理审批",
        vec![
            paragraph(
                "",
                "先冻结真实 controller 签署的候选，请求审批后仍不提交业务。管理员核对原候选，使用身份控制 Recovery Key 批准；最终由原请求者提交同一 Event。",
            ),
            field(
                scope,
                context.clone(),
                "management-review-principal",
                "Agent Account: principal_id",
                principal,
                editable,
                false,
                move |next| {
                    principal.revise(|value| {
                        *value = next;
                    });
                    loaded.revise(|value| {
                        *value = None;
                    });
                    confirmed.revise(|value| {
                        *value = false;
                    });
                },
            ),
            field(
                scope,
                context.clone(),
                "management-review-station",
                "Agent Account: station_id",
                station,
                editable,
                false,
                move |next| {
                    station.revise(|value| {
                        *value = next;
                    });
                    loaded.revise(|value| {
                        *value = None;
                    });
                    confirmed.revise(|value| {
                        *value = false;
                    });
                },
            ),
            choice(
                scope,
                context.clone(),
                "management-review-operation",
                "原管理意图",
                operation,
                vec![
                    ("join".into(), "加入当前 Realm".into()),
                    (
                        "publish".into(),
                        "公开当前 Realm 的 Agent interaction".into(),
                    ),
                ],
                editable,
                move |next| {
                    operation.revise(|value| {
                        *value = next;
                    });
                    loaded.revise(|value| {
                        *value = None;
                    });
                    confirmed.revise(|value| {
                        *value = false;
                    });
                },
            ),
            action(
                scope,
                context.clone(),
                "management-review-request",
                "冻结候选并请求审批（不提交业务）",
                "primary",
                scope.bond(move || !busy.get() && decision.get().is_none()),
                move || request.request(),
            ),
            field(
                scope,
                context.clone(),
                "management-review-request-json",
                "粘贴原审批请求分享内容",
                shared,
                editable,
                true,
                move |next| {
                    shared.revise(|value| {
                        *value = next;
                    });
                    loaded.revise(|value| {
                        *value = None;
                    });
                    confirmed.revise(|value| {
                        *value = false;
                    });
                },
            ),
            action(
                scope,
                context.clone(),
                "management-review-load",
                "读取真实审批状态并核对摘要",
                "secondary",
                editable,
                move || load.load(),
            ),
            details,
            status(state.status),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes_with_class(app: &glory::ui::App, class: &str) -> Vec<glory::render::NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut found = Vec::new();
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            pending.extend(node.children.iter().copied());
            if node
                .descriptor
                .view()
                .classes
                .iter()
                .any(|found| found == class)
            {
                found.push(id);
            }
        }
        found
    }

    fn retry_nodes(app: &glory::ui::App) -> Vec<glory::render::NodeId> {
        nodes_with_class(app, "management-review-retry-decision")
    }

    fn retry_enabled(app: &glory::ui::App, id: glory::render::NodeId) -> bool {
        let tree = app.tree();
        let glory::render::Props::Button(button) = tree.node(id).unwrap().descriptor.view().props
        else {
            panic!("actual retry Button required")
        };
        button.enabled
    }

    #[test]
    fn retry_action_requires_a_retained_original_decision() {
        let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
        let scope = app.scope();
        let retained = scope.cage(false);
        let enabled = scope.cage(false);
        app.mount(retry_decision_action(
            context,
            scope.bond(move || retained.get()),
            scope.bond(move || enabled.get()),
            || {},
        ))
        .unwrap();
        app.flush().unwrap();
        assert!(
            retry_nodes(&app).is_empty(),
            "there is no original decision to retry"
        );
        for _ in 0..4 {
            retained.revise(|value| *value = true);
            app.flush().unwrap();
            let nodes = retry_nodes(&app);
            assert_eq!(nodes.len(), 1);
            let old = nodes[0];
            assert!(
                !retry_enabled(&app, old),
                "a retained decision still needs explicit confirmation"
            );
            enabled.revise(|value| *value = true);
            app.flush().unwrap();
            assert!(retry_enabled(&app, old));
            retained.revise(|value| *value = false);
            app.flush().unwrap();
            assert!(retry_nodes(&app).is_empty());
            assert!(
                app.tree().node(old).is_err(),
                "retired original decisions have no live action node"
            );
            enabled.revise(|value| *value = false);
        }
    }

    #[test]
    fn retained_decision_retires_the_fresh_approval_form() {
        let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
        let scope = app.scope();
        let retained = scope.cage(false);
        let confirmed = scope.cage(true);
        let busy = scope.cage(false);
        let state = ReviewPage {
            context: context.clone(),
            owner: scope.downgrade(),
            realm: "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6".into(),
            principal: scope.cage(String::new()),
            station: scope.cage(String::new()),
            operation: scope.cage("join".into()),
            loaded: scope.cage(None),
            retained_request: scope.cage(None),
            retained_decision: scope.cage(None),
            shared: scope.cage(String::new()),
            recovery: scope.cage(Zeroizing::new(String::new())),
            root_generation: scope.cage("0".into()),
            confirmed,
            status: scope.cage(String::new()),
            busy,
        };
        app.mount(stack(
            "review-decision-test",
            vec![
                fresh_decision_controls(
                    state,
                    scope.bond(move || retained.get()),
                    scope.bond(move || !busy.get() && confirmed.get() && !retained.get()),
                ),
                retry_decision_action(
                    context,
                    scope.bond(move || retained.get()),
                    scope.bond(move || !busy.get() && confirmed.get()),
                    || {},
                ),
            ],
        ))
        .unwrap();
        app.flush().unwrap();
        for _ in 0..4 {
            assert_eq!(nodes_with_class(&app, "management-review-approve").len(), 1);
            assert_eq!(nodes_with_class(&app, "management-review-reject").len(), 1);
            assert!(retry_nodes(&app).is_empty());
            let old = nodes_with_class(&app, "management-review-new-decision-controls")[0];
            let old_approve = nodes_with_class(&app, "management-review-approve")[0];
            let old_reject = nodes_with_class(&app, "management-review-reject")[0];
            retained.revise(|value| *value = true);
            confirmed.revise(|value| *value = false);
            app.flush().unwrap();
            assert_eq!(
                nodes_with_class(&app, "management-review-approve").len(),
                0,
                "an original decision awaiting reconciliation cannot offer another approval"
            );
            assert!(nodes_with_class(&app, "management-review-reject").is_empty());
            assert!(nodes_with_class(&app, "management-review-new-decision-controls").is_empty());
            for id in [old, old_approve, old_reject] {
                assert!(
                    app.tree().node(id).is_err(),
                    "old signing controls must retire"
                );
            }
            let retry = retry_nodes(&app);
            assert_eq!(retry.len(), 1);
            assert!(!retry_enabled(&app, retry[0]));
            confirmed.revise(|value| *value = true);
            app.flush().unwrap();
            assert!(
                retry_enabled(&app, retry[0]),
                "only the original decision can be retried"
            );
            retained.revise(|value| *value = false);
            app.flush().unwrap();
        }
    }
}
