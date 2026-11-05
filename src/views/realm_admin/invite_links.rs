use std::rc::Rc;

use glory::prelude::*;
use zeroize::Zeroize;

use crate::presentation::widgets::{empty, heading, input_field, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::transport::realm_invite_link::{PendingRealmInviteLink, parse_realm_invite_link};

const JOINED_MESSAGE: &str =
    "Joined. Membership is accepted; encrypted access follows the Realm's normal security flow.";

async fn joined_link_message(
    http: &arkret_sdk::http_client::Client,
    authority: &arkret_sdk::AccountId,
    realm: &arkret_sdk::RealmId,
    store: crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<String> {
    crate::realm_events_engine::refresh_joined_realm(http, authority, realm, store).await?;
    Ok(JOINED_MESSAGE.into())
}

pub(crate) async fn link_join_completion_message(
    http: &arkret_sdk::http_client::Client,
    authority: &arkret_sdk::AccountId,
    realm: &arkret_sdk::RealmId,
    store: crate::runtime::input::StateStoreHandle,
    progress: &crate::models::EventSubmissionProgress,
) -> anyhow::Result<String> {
    if !progress.is_committed() {
        return Ok("Join submitted; authority acceptance is still pending.".into());
    }
    joined_link_message(http, authority, realm, store).await
}

enum LinkJoinAttempt {
    Accept(arkret_sdk::RealmInviteLinkToken),
    Readback(arkret_sdk::RealmId),
}

fn link_join_attempt(
    input: &str,
    accepted: Option<arkret_sdk::RealmId>,
) -> anyhow::Result<LinkJoinAttempt> {
    if input.is_empty()
        && let Some(realm) = accepted
    {
        return Ok(LinkJoinAttempt::Readback(realm));
    }
    Ok(LinkJoinAttempt::Accept(parse_realm_invite_link(input)?))
}

pub(crate) fn page(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm_id: Option<String>,
    initial_input: Option<Cage<String>>,
) -> View {
    let input = initial_input.unwrap_or_else(|| scope.cage(String::new()));
    let message = scope.cage(String::new());
    let busy = scope.cage(false);
    let pending = scope.cage(None::<PendingRealmInviteLink>);
    let accepted_join = scope.cage(None::<arkret_sdk::RealmId>);
    let share = scope.cage(String::new());
    let landing = scope.cage("https://arkret.org".to_owned());
    let days = scope.cage("7".to_owned());
    let max_uses = scope.cage("1".to_owned());
    let views = scope.cage(Vec::<arkret_sdk::RealmInviteLinkView>::new());
    let previous_generation = scope.cage(context.session_generation.get_untracked());
    let cleanup_input = input;
    let cleanup_share = share;
    if let Err(error) = scope.on_cleanup(move || {
        let _ = cleanup_input.try_revise(|value| value.zeroize());
        let _ = cleanup_share.try_revise(|value| value.zeroize());
    }) {
        scope.report_error(error);
    }
    let reset_context = context.clone();
    scope.effect(move || {
        let generation = reset_context.session_generation.get();
        if generation == previous_generation.get_untracked() {
            return;
        }
        previous_generation.revise(|value| *value = generation);
        input.revise(|value| value.zeroize());
        pending.revise(|value| *value = None);
        accepted_join.revise(|value| *value = None);
        share.revise(|value| value.zeroize());
        views.revise(|value| value.clear());
        busy.revise(|value| *value = false);
        message.revise(|value| value.clear());
    });

    let account_context = context.clone();
    let account_label = scope.bond(move || {
        account_context
            .active_account
            .get()
            .map(|account| {
                format!(
                    "{} @ {}",
                    account.authority.principal_id, account.authority.station_id
                )
            })
            .unwrap_or_else(|| {
                "Sign in and choose an account first; then reopen the invitation.".into()
            })
    });
    let title = if realm_id.is_some() {
        "Share a Realm invitation"
    } else {
        "Join from an invitation link"
    };
    let mut children = vec![
        heading(3, "", title),
        paragraph("", account_label),
        paragraph(
            "muted",
            "Choose a different account with the account switcher before confirming. Opening or previewing a link does not join.",
        ),
    ];

    if let Some(realm) = realm_id {
        children.push(input_field(
            context.clone(),
            "realm-invite-link-days",
            "Lifetime in days",
            days,
            Purpose::Text,
        ));
        children.push(input_field(
            context.clone(),
            "realm-invite-link-max-uses",
            "Maximum different accounts",
            max_uses,
            Purpose::Text,
        ));
        children.push(input_field(
            context.clone(),
            "realm-invite-link-landing",
            "Share landing URL",
            landing,
            Purpose::Url,
        ));
        children.push(paragraph(
            "muted",
            "Default: 7 days and one account. Lost link secrets cannot be recovered; revoke and create a new link.",
        ));

        let prepare_context = context.clone();
        let prepare_enabled_context = prepare_context.clone();
        let prepare_realm = realm.clone();
        children.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn btn-primary realm-invite-link-prepare")
                .label("Prepare invitation")
                .enabled(scope.bond(move || {
                    !busy.get()
                        && prepare_enabled_context.active_account.get().is_some()
                        && pending.get().is_none()
                }))
                .on_press(move || {
                    let Some(account) = prepare_context.active_account.get() else {
                        return;
                    };
                    let Some(seconds) = days
                        .get_untracked()
                        .parse::<u32>()
                        .ok()
                        .and_then(|value| value.checked_mul(86400))
                    else {
                        message.revise(|value| *value = "Choose valid positive limits".into());
                        return;
                    };
                    let Ok(uses) = max_uses.get_untracked().parse::<u32>() else {
                        message.revise(|value| *value = "Choose valid positive limits".into());
                        return;
                    };
                    let Some(scope) = prepare_context.root_scope() else {
                        return;
                    };
                    let base = prepare_context.base_url.get();
                    let token = prepare_context.token.get();
                    let authority = account.authority.clone();
                    let realm = prepare_realm.clone();
                    let generation = prepare_context.session_generation.get();
                    let active = Some(account);
                    busy.revise(|value| *value = true);
                    let operation_context = prepare_context.clone();
                    let _ = scope.owner().spawn(async move {
                        let result = crate::transport::auth::with_authed_api(
                            &base,
                            token,
                            |api| async move {
                                api.prepare_realm_invite_link(
                                    &authority,
                                    &arkret_sdk::RealmId::new(realm)?,
                                    seconds,
                                    uses,
                                )
                                .await
                            },
                        )
                        .await;
                        if !operation_context.session_matches(generation, &active) {
                            return;
                        }
                        busy.revise(|value| *value = false);
                        match result {
                            Ok(value) => {
                                pending.revise(|current| *current = Some(value));
                                message.revise(|value| {
                                    *value = "Invitation is prepared locally. Publish it to obtain authority acceptance.".into()
                                });
                            }
                            Err(error) => message.revise(|value| *value = error.display()),
                        }
                    });
                }),
        ) as View);

        let pending_context = context.clone();
        children.push(reactive(pending, move |_scope, saved| {
            let Some(saved) = saved else {
                return empty();
            };
            let mut actions = vec![];
            let publish_context = pending_context.clone();
            actions.push(Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn btn-primary realm-invite-link-publish")
                    .label("Publish / retry same invitation")
                    .on_press(move || {
                        let Some(account) = publish_context.active_account.get() else {
                            return;
                        };
                        let Some(scope) = publish_context.root_scope() else {
                            return;
                        };
                        let mut saved = saved.clone();
                        let authority = account.authority.clone();
                        let base = publish_context.base_url.get();
                        let token = publish_context.token.get();
                        let generation = publish_context.session_generation.get();
                        let active = Some(account);
                        let landing = landing.get_untracked();
                        busy.revise(|value| *value = true);
                        let operation_context = publish_context.clone();
                        let _ = scope.owner().spawn(async move {
                            let result = crate::transport::auth::with_authed_api(
                                &base,
                                token,
                                |api| async move {
                                    let outcome = api
                                        .publish_realm_invite_link(&mut saved, &authority)
                                        .await;
                                    Ok((saved, outcome))
                                },
                            )
                            .await;
                            if !operation_context.session_matches(generation, &active) {
                                return;
                            }
                            busy.revise(|value| *value = false);
                            match result {
                                Ok((saved, outcome)) => {
                                    match outcome {
                                        Ok(_) => match saved.share_url(&landing) {
                                            Ok(url) => {
                                                share.revise(|value| *value = url.to_string());
                                                message.revise(|value| {
                                                    *value = "Accepted. Copy and share the link yourself.".into()
                                                });
                                            }
                                            Err(_) => message.revise(|value| {
                                                *value = "Accepted; use a valid HTTPS landing URL to display the link.".into()
                                            }),
                                        },
                                        Err(_) => message.revise(|value| {
                                            *value = "Awaiting acceptance. Retry this same invitation; its Event and secret are retained only in this session.".into()
                                        }),
                                    }
                                    pending.revise(|value| *value = Some(saved));
                                }
                                Err(error) => message.revise(|value| *value = error.display()),
                            }
                        });
                    }),
            ) as View);
            actions.push(Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn btn-secondary realm-invite-link-discard")
                    .label("Discard local secret")
                    .on_press(move || {
                        pending.revise(|value| *value = None);
                        share.revise(|value| value.zeroize());
                        message.revise(|value| {
                            *value = "Local secret discarded. Any accepted invitation remains active until revoked below.".into()
                        });
                    }),
            ) as View);
            actions.push(Box::new(
                sapid::text_field()
                    .unstyled()
                    .class("realm-invite-link-share")
                    .value(share)
                    .multiline(true)
                    .enabled(false),
            ) as View);
            stack("realm-invite-link-pending", actions)
        }));

        let refresh_context = context.clone();
        let refresh_realm = realm.clone();
        children.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn btn-secondary realm-invite-link-refresh")
                .label("Refresh invitation status")
                .on_press(move || {
                    let Some(scope) = refresh_context.root_scope() else {
                        return;
                    };
                    let base = refresh_context.base_url.get();
                    let token = refresh_context.token.get();
                    let realm = refresh_realm.clone();
                    let generation = refresh_context.session_generation.get();
                    let active = refresh_context.active_account.get();
                    busy.revise(|value| *value = true);
                    let operation_context = refresh_context.clone();
                    let _ = scope.owner().spawn(async move {
                        let result = crate::transport::auth::with_authed_api(
                            &base,
                            token,
                            |api| async move {
                                api.realm_invite_link_views(&arkret_sdk::RealmId::new(realm)?)
                                    .await
                            },
                        )
                        .await;
                        if !operation_context.session_matches(generation, &active) {
                            return;
                        }
                        busy.revise(|value| *value = false);
                        match result {
                            Ok(value) => views.revise(|current| *current = value),
                            Err(error) => message.revise(|value| *value = error.display()),
                        }
                    });
                }),
        ) as View);
        let list_context = context.clone();
        children.push(reactive(views, move |_, rows| {
            let rows = rows
                .into_iter()
                .map(|view| {
                    let revoke_context = list_context.clone();
                    let label = format!(
                        "{} — {}/{}; expires {}; {:?} (as of {})",
                        view.realm_invite_link_id,
                        view.use_count,
                        view.max_uses,
                        view.expires_at,
                        view.status,
                        view.as_of
                    );
                    stack(
                        "realm-invite-link-row",
                        vec![
                            paragraph("", label),
                            Box::new(
                                sapid::button()
                                    .unstyled()
                                    .class("btn btn-danger realm-invite-link-revoke")
                                    .label("Revoke")
                                    .enabled(view.status != arkret_sdk::RealmInviteLinkStatus::Revoked)
                                    .on_press(move || {
                                        let Some(account) = revoke_context.active_account.get() else {
                                            return;
                                        };
                                        let Some(scope) = revoke_context.root_scope() else {
                                            return;
                                        };
                                        let authority = account.authority.clone();
                                        let base = revoke_context.base_url.get();
                                        let token = revoke_context.token.get();
                                        let generation = revoke_context.session_generation.get();
                                        let active = Some(account);
                                        let view = view.clone();
                                        busy.revise(|value| *value = true);
                                        let operation_context = revoke_context.clone();
                                        let _ = scope.owner().spawn(async move {
                                            let result = crate::transport::auth::with_authed_api(
                                                &base,
                                                token,
                                                |api| async move {
                                                    api.revoke_realm_invite_link(
                                                        &view.realm_id,
                                                        &view.realm_invite_link_id,
                                                        &authority,
                                                    )
                                                    .await
                                                },
                                            )
                                            .await;
                                            if !operation_context.session_matches(generation, &active) {
                                                return;
                                            }
                                            busy.revise(|value| *value = false);
                                            match result {
                                                Ok(progress) if progress.is_committed() => message.revise(|value| {
                                                    *value = "Revoked. Existing members keep their membership; refresh to see the new state.".into()
                                                }),
                                                Ok(_) => message.revise(|value| {
                                                    *value = "Revocation is pending authority acceptance.".into()
                                                }),
                                                Err(error) => message.revise(|value| *value = error.display()),
                                            }
                                        });
                                    }),
                            ) as View,
                        ],
                    )
                })
                .collect();
            stack("realm-invite-link-list", rows)
        }));
    } else {
        children.push(input_field(
            context.clone(),
            "realm-invite-link-input",
            "Paste invitation link after signing in",
            input,
            Purpose::Password,
        ));
        for (label, accept) in [
            ("Preview without joining", false),
            ("Confirm: join with this account", true),
        ] {
            let action_context = context.clone();
            children.push(Box::new(
                sapid::button()
                    .unstyled()
                    .class(if accept {
                        "btn btn-primary realm-invite-link-confirm"
                    } else {
                        "btn btn-secondary realm-invite-link-preview"
                    })
                    .label(label)
                    .on_press(move || {
                        let Some(account) = action_context.active_account.get() else {
                            return;
                        };
                        if busy.get_untracked() {
                            return;
                        }
                        let attempt = match link_join_attempt(
                            &input.get_untracked(),
                            if accept { accepted_join.get_untracked() } else { None },
                        ) {
                            Ok(value) => value,
                            Err(_) => {
                                message.revise(|value| *value = "Invalid invitation link".into());
                                return;
                            }
                        };
                        if accept && matches!(&attempt, LinkJoinAttempt::Accept(_)) {
                            accepted_join.revise(|value| *value = None);
                        }
                        let Some(scope) = action_context.root_scope() else {
                            return;
                        };
                        if accept {
                            input.revise(|value| value.zeroize());
                        }
                        let authority = account.authority.clone();
                        let base = action_context.base_url.get();
                        let token = action_context.token.get();
                        let generation = action_context.session_generation.get();
                        let active = Some(account);
                        busy.revise(|value| *value = true);
                        let operation_context = action_context.clone();
                        let submission_store = operation_context.state_store.handle();
                        let acceptance_context = operation_context.clone();
                        let acceptance_account = active.clone();
                        let _ = scope.owner().spawn(async move {
                            let result = crate::transport::auth::with_authed_api(
                                &base,
                                token,
                                |api| async move {
                                    match attempt {
                                        LinkJoinAttempt::Readback(realm) => {
                                            joined_link_message(&api.sdk_http_client()?, &authority, &realm, submission_store).await
                                        }
                                        LinkJoinAttempt::Accept(credential) if accept => {
                                            let progress = api.accept_realm_invite_link(&credential, &authority).await?;
                                            anyhow::ensure!(acceptance_context.session_matches(generation, &acceptance_account), "join account session changed");
                                            if progress.is_committed() {
                                                accepted_join.revise(|value| *value = Some(credential.realm_id.clone()));
                                            }
                                            link_join_completion_message(
                                                &api.sdk_http_client()?, &authority, &credential.realm_id,
                                                submission_store, &progress,
                                            ).await
                                        }
                                        LinkJoinAttempt::Accept(credential) => {
                                            api.preview_realm_invite_link(&credential, &authority).await.map(|value| {
                                                format!("Preview: {}. Confirm below to join with the displayed account.",
                                                    value.preview.display_name.unwrap_or_else(|| value.preview.realm_id.to_string()))
                                            })
                                        }
                                    }
                                },
                            )
                            .await;
                            if !operation_context.session_matches(generation, &active) {
                                return;
                            }
                            busy.revise(|value| *value = false);
                            match result {
                                Ok(value) => message.revise(|current| *current = value),
                                Err(_) if accept && accepted_join.get_untracked().is_some() => message.revise(|value| {
                                    *value = "Membership is accepted, but live synchronization is pending. Confirm again to retry synchronization without submitting another invitation.".into()
                                }),
                                Err(_) if accept => message.revise(|value| {
                                    *value = "Invitation could not be accepted. Reopen the link to retry; pending exact Events continue through the durable queue.".into()
                                }),
                                Err(_) => message.revise(|value| {
                                    *value = "Preview is unavailable or restricted. It does not determine final admission.".into()
                                }),
                            }
                        });
                    }),
            ) as View);
        }
    }
    children.push(paragraph("realm-invite-link-message", message));
    stack("event realm-invite-links", children)
}

pub(crate) fn landing(scope: &Scope, context: Rc<InksonContext>) -> View {
    let Some(value) = take_browser_invite() else {
        return empty();
    };
    let input = scope.cage(value);
    let open = scope.cage(true);
    reactive(open, move |scope, is_open| {
        if !is_open {
            return empty();
        }
        stack(
            "realm-invite-link-landing",
            vec![
                paragraph(
                    "muted",
                    "The invitation secret has been removed from the address bar. Choose an account before confirming.",
                ),
                page(scope, context.clone(), None, Some(input)),
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn btn-secondary realm-invite-link-close")
                        .label("Close invitation")
                        .on_press(move || {
                            input.revise(|value| value.zeroize());
                            open.revise(|value| *value = false);
                        }),
                ) as View,
            ],
        )
    })
}

#[cfg(target_arch = "wasm32")]
fn take_browser_invite() -> Option<String> {
    let window = web_sys::window()?;
    let fragment = window.location().hash().ok()?;
    if !fragment.starts_with("#realm/") || !fragment.contains("lt=invite") {
        return None;
    }
    let path = window.location().pathname().ok()?;
    let query = window.location().search().ok()?;
    window
        .history()
        .ok()?
        .replace_state_with_url(
            &wasm_bindgen::JsValue::NULL,
            "",
            Some(&format!("{path}{query}")),
        )
        .ok()?;
    let value = format!("web+arkret:{}", &fragment[1..]);
    parse_realm_invite_link(&value).ok()?;
    Some(value)
}

#[cfg(not(target_arch = "wasm32"))]
fn take_browser_invite() -> Option<String> {
    None
}

#[cfg(test)]
mod join_retry_tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn retiring_invite_page_cleans_live_parent_input_without_accessing_retired_state() {
        let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
        for (supplied, retire_input_first) in [(false, false), (true, false), (true, true)] {
            let input_owner = app.scope().child().unwrap();
            let input = input_owner.cage("fixture-private-invitation".to_owned());
            let owner = app.scope().child().unwrap();
            let view = page(&owner, context.clone(), None, supplied.then_some(input));
            drop(view);
            if retire_input_first {
                input_owner.dispose();
            }
            owner.dispose();
            if supplied && !retire_input_first {
                assert!(
                    input.get_untracked().is_empty(),
                    "retiring the invitation must erase a still-live supplied input"
                );
            }
            input_owner.dispose();
            assert!(app.scope().is_alive());
        }
    }

    #[test]
    fn accepted_join_retry_reads_the_same_realm_without_an_invitation_secret() {
        let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [17; 32],
        ));
        assert!(
            matches!(link_join_attempt("", Some(realm.clone())).unwrap(),
            LinkJoinAttempt::Readback(target) if target == realm)
        );
        assert!(link_join_attempt("", None).is_err());
        assert!(link_join_attempt("invalid replacement link", Some(realm)).is_err());
    }
}
