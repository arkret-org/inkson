//! Circle authoring keeps expected membership revisions and durable MLS intent.
use super::*;

#[derive(Clone)]
pub(super) enum Change {
    SelfMembership {
        realm: String,
        circle: String,
        member: arkret_sdk::ActorId,
        target: arkret_sdk::CircleMembership,
        expected: Option<arkret_sdk::CircleMembership>,
    },
    Member {
        realm: String,
        circle: String,
        member: arkret_sdk::ActorId,
        state: arkret_sdk::CircleMembership,
    },
    Remove {
        realm: String,
        circle: String,
        member: arkret_sdk::ActorId,
    },
    Update {
        realm: String,
        circle: String,
        title: String,
        summary: String,
        display: arkret_sdk::CircleDisplay,
        visibility: arkret_sdk::CircleDirectoryVisibility,
        rule: arkret_sdk::CircleJoinRule,
    },
    Restrict {
        realm: String,
        circle: String,
    },
    Tombstone {
        realm: String,
        circle: String,
    },
    Archive {
        realm: String,
        circle: String,
        restore: bool,
    },
}
impl Change {
    fn messages(&self) -> (&'static str, &'static str) {
        match self {
            Self::SelfMembership {
                target: arkret_sdk::CircleMembership::Knock,
                ..
            } => (
                "circles.feedback.join_requested",
                "circles.feedback.membership_failed",
            ),
            Self::SelfMembership { .. } | Self::Member { .. } => (
                "circles.feedback.membership_updated",
                "circles.feedback.membership_failed",
            ),
            Self::Remove { .. } => (
                "circles.feedback.member_removed",
                "circles.feedback.member_removal_failed",
            ),
            Self::Update { .. } => ("circles.feedback.updated", "circles.feedback.update_failed"),
            Self::Restrict { .. } => (
                "circles.feedback.history_restricted",
                "circles.feedback.history_failed",
            ),
            Self::Tombstone { .. } => {
                ("circles.feedback.retired", "circles.feedback.retire_failed")
            }
            Self::Archive { restore: true, .. } => (
                "circles.feedback.restored",
                "circles.feedback.restore_failed",
            ),
            Self::Archive { restore: false, .. } => (
                "circles.feedback.archived",
                "circles.feedback.archive_failed",
            ),
        }
    }
}
pub(super) fn run(scope: &Scope, context: Rc<InksonContext>, ui: Rc<CircleUi>, change: Change) {
    if ui.busy.get_untracked() {
        return;
    }
    let generation = context.session_generation.get();
    let account = context.active_account.get();
    let weak = scope.downgrade();
    let base = context.base_url.get();
    let credential = context.token.get();
    let principal = crate::app::principal_id_owned(context.principal_id.get());
    let (success, failure) = change.messages();
    ui.busy.revise(|value| *value = true);
    let _ = scope.spawn(async move {
        let outcome = with_authed_api(&base, credential, |api| async move {
            let submitter = api.event_submitter()?;
            match change {
                Change::SelfMembership {
                    realm,
                    circle,
                    member,
                    target,
                    expected,
                } => {
                    let parent = if target == arkret_sdk::CircleMembership::Join {
                        Some(
                            submitter
                                .read_parent_membership_revision(
                                    &arkret_sdk::RealmId::new(realm.clone())?,
                                    &member,
                                )
                                .await?,
                        )
                    } else {
                        None
                    };
                    let event = crate::operation::ak_ops::circle_member_state_with_expected(
                        &realm,
                        &principal,
                        &circle,
                        &member,
                        target,
                        expected
                            .map(arkret_wire::WirePresence::Value)
                            .unwrap_or(arkret_wire::WirePresence::Missing),
                        parent,
                    )?
                    .build_sdk_event("inkson")?;
                    let body = arkret_sdk::CircleMemberRequestBody {
                        member_event: arkret_wire::EventAdmissionSubmission::new(
                            submitter
                                .author_for_direct_submission(&event)
                                .await?
                                .into_event(),
                        ),
                    };
                    api.http()
                        .circle_member_add(&circle, &submitter.verify_publication(body)?)
                        .await?;
                }
                Change::Member {
                    realm,
                    circle,
                    member,
                    state,
                } => {
                    crate::transport::circle::add_circle_member(
                        &submitter, &realm, &principal, &circle, &member, state,
                    )
                    .await?;
                }
                Change::Remove {
                    realm,
                    circle,
                    member,
                } => {
                    crate::transport::circle::remove_circle_member(
                        &submitter, &realm, &principal, &circle, &member,
                    )
                    .await?;
                }
                Change::Update {
                    realm,
                    circle,
                    title,
                    summary,
                    display,
                    visibility,
                    rule,
                } => {
                    let event = crate::operation::ak_ops::circle_update(
                        &realm, &principal, &circle, &title, &summary, display, visibility, rule,
                    )?
                    .build_sdk_event("inkson")?;
                    submitter.submit_sdk_event(&event).await?;
                }
                Change::Restrict { realm, circle } => {
                    let event = crate::operation::ak_ops::circle_restrict_history(
                        &realm, &principal, &circle,
                    )?
                    .build_sdk_event("inkson")?;
                    submitter.submit_sdk_event(&event).await?;
                }
                Change::Tombstone { realm, circle } => {
                    let event = crate::operation::ak_ops::circle_lifecycle(
                        &realm,
                        &principal,
                        &circle,
                        arkret_sdk::EventKind::CircleTombstone,
                        None,
                    )?
                    .build_sdk_event("inkson")?;
                    submitter.submit_sdk_event(&event).await?;
                }
                Change::Archive {
                    realm,
                    circle,
                    restore,
                } => {
                    if restore {
                        crate::transport::circle::restore_circle(
                            &submitter, &realm, &principal, &circle, None,
                        )
                        .await?;
                    } else {
                        crate::transport::circle::archive_circle(
                            &submitter, &realm, &principal, &circle, None,
                        )
                        .await?;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        if weak.upgrade().is_none() || !context.session_matches(generation, &account) {
            return;
        }
        ui.status.revise(|value| {
            *value = match outcome {
                Ok(()) => {
                    ui.refresh.revise(|value| *value = value.wrapping_add(1));
                    CircleFeedback::new(success)
                }
                Err(error) => CircleFeedback::new(failure).with_api_error(error),
            }
        });
        ui.busy.revise(|value| *value = false);
    });
}

pub(super) struct Create {
    pub title: String,
    pub summary: String,
    pub short_name: String,
    pub visibility: arkret_sdk::CircleDirectoryVisibility,
    pub rule: arkret_sdk::CircleJoinRule,
    pub history: arkret_sdk::HistoryAccess,
    pub encrypted: bool,
}
pub(super) fn create(
    scope: &Scope,
    context: Rc<InksonContext>,
    ui: Rc<CircleUi>,
    realm: String,
    form: Create,
) {
    if ui.busy.get_untracked() {
        return;
    }
    let Ok(realm_id) = arkret_sdk::RealmId::new(realm.clone()) else {
        ui.status
            .revise(|value| *value = CircleFeedback::new("circles.feedback.invalid_realm"));
        return;
    };
    let principal = crate::app::principal_id_owned(context.principal_id.get());
    let Ok(actor) = arkret_sdk::DidCoreId::new(principal.clone()) else {
        ui.status
            .revise(|value| *value = CircleFeedback::new("circles.feedback.invalid_account"));
        return;
    };
    let mut display = crate::operation::ak_ops::circle_display_from_title(&form.title);
    if !form.short_name.trim().is_empty() {
        display.short_name = form.short_name.trim().to_owned();
    }
    let event = crate::operation::ak_ops::circle_create(
        realm_id.as_str(),
        &principal,
        crate::operation::ak_ops::CircleCreateOptions {
            title: &form.title,
            summary: Some(&form.summary),
            display,
            directory_visibility: form.visibility,
            join_rule: form.rule,
            history_access: form.history,
        },
    )
    .and_then(|builder| builder.build_sdk_event("inkson"));
    let event = match event {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(%error,"Circle create event preparation failed");
            ui.status
                .revise(|value| *value = CircleFeedback::new("circles.feedback.prepare_failed"));
            return;
        }
    };
    let creator = event.actor_id().clone();
    let account = context.active_account.get();
    let generation = context.session_generation.get();
    let store = context.state_store.handle();
    let weak = scope.downgrade();
    let base = context.base_url.get();
    let credential = context.token.get();
    let owner_account = account.clone();
    ui.busy.revise(|value| *value = true);
    ui.status
        .revise(|value| *value = CircleFeedback::new("circles.feedback.creating"));
    let _ = scope.spawn(async move {
        let outcome = with_authed_api(&base, credential, |api| async move {
            let submitter = api.event_submitter()?;
            if form.encrypted {
                let account = account.ok_or_else(|| {
                    anyhow::anyhow!("encrypted Circle requires an active account")
                })?;
                let circle = submitter
                    .submit_circle_creator_durable(&event, &account.device_id)
                    .await?;
                let scope = arkret_sdk::ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle.clone(),
                };
                crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(
                    &api,
                    &store,
                    &scope,
                    &account.authority,
                    &account.device_id,
                    false,
                )
                .await
                .map_err(anyhow::Error::msg)?;
                return Ok::<_, anyhow::Error>(circle.to_string());
            }
            let parent = submitter
                .read_parent_membership_revision(&realm_id, &creator)
                .await?;
            let request = arkret_sdk::CircleCreateRequestBody {
                create_event: arkret_wire::EventAdmissionSubmission::new(
                    submitter
                        .author_for_direct_submission(&event)
                        .await?
                        .into_event(),
                ),
            };
            let created = api
                .http()
                .circle_create(&submitter.verify_publication(request)?)
                .await?;
            crate::transport::circle::submit_circle_member_with_parent_revision(
                &submitter,
                created.realm_id.as_str(),
                actor.as_str(),
                created.circle_id.as_str(),
                &creator,
                arkret_sdk::CircleMembership::Join,
                Some(parent),
            )
            .await?;
            Ok(created.circle_id.to_string())
        })
        .await;
        if weak.upgrade().is_none() || !context.session_matches(generation, &owner_account) {
            return;
        }
        match outcome {
            Ok(circle_id) => {
                ui.create_open.revise(|value| *value = false);
                ui.refresh.revise(|value| *value = value.wrapping_add(1));
                ui.status
                    .revise(|value| *value = CircleFeedback::new("circles.feedback.created"));
                context.navigate(Route::CircleDetail {
                    realm_id: realm,
                    circle_id,
                });
            }
            Err(error) => ui.status.revise(|value| {
                *value = CircleFeedback::new("circles.feedback.create_failed").with_api_error(error)
            }),
        }
        ui.busy.revise(|value| *value = false);
    });
}
