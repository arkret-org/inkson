use dioxus::prelude::*;
use dioxus_router::Link;

use crate::components::HelpTip;
use crate::routes::Route;
use crate::transport::auth::with_authed_api;

fn lifecycle_label(state: arkret_sdk::CircleState) -> &'static str {
    match state {
        arkret_sdk::CircleState::Active => "Active",
        arkret_sdk::CircleState::Archived => "Archived",
        arkret_sdk::CircleState::Tombstoned => "Tombstoned",
    }
}

fn membership_label(state: Option<arkret_sdk::CircleMembership>) -> &'static str {
    match state {
        Some(arkret_sdk::CircleMembership::Join) => "Member",
        Some(arkret_sdk::CircleMembership::Knock) => "Requested",
        Some(arkret_sdk::CircleMembership::Leave) => "Left",
        Some(arkret_sdk::CircleMembership::Ban) => "Banned",
        None => "Directory viewer",
    }
}

fn encryption_label(mls_group_id: Option<&str>) -> &'static str {
    if mls_group_id.is_some() {
        "Independent MLS group · E2EE active"
    } else {
        "Restricted delivery · not E2EE"
    }
}

#[component]
pub fn CirclesPanel(
    realm_id: String,
    selected_circle_id: Option<String>,
    principal_id: String,
    token: Signal<String>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let navigator = dioxus_router::hooks::use_navigator();
    let mut circles = use_signal(Vec::<arkret_sdk::CircleView>::new);
    let mut loading = use_signal(|| true);
    let mut status = use_signal(String::new);
    let mut refresh = use_signal(|| 0_u64);
    let mut create_open = use_signal(|| false);
    let mut create_title = use_signal(String::new);
    let mut create_summary = use_signal(String::new);
    let mut member_actor = use_signal(String::new);
    let mut member_state = use_signal(|| "invite".to_owned());
    let mut busy = use_signal(|| false);

    {
        let base_url = base_url.clone();
        let realm_id = realm_id.clone();
        use_effect(move || {
            let _ = refresh();
            let base = base_url.clone();
            let realm = realm_id.clone();
            let credential = token();
            loading.set(true);
            spawn(async move {
                let outcome = with_authed_api(&base, credential, |api| async move {
                    api.http()
                        .circle_list(&realm)
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await;
                match outcome {
                    Ok(list) => {
                        circles.set(crate::circle::ordinary_circle_views(list));
                        status.set(String::new());
                    }
                    Err(error) => {
                        circles.set(Vec::new());
                        status.set(format!("Could not load Circles: {}", error.display()));
                    }
                }
                loading.set(false);
            });
        });
    }

    let selected = selected_circle_id.as_deref().and_then(|id| {
        circles()
            .into_iter()
            .find(|circle| circle.circle_id.as_str() == id)
    });
    let create_disabled = busy() || create_title().trim().is_empty();

    rsx! {
        main { class: "circle-realm", "data-testid": "circles-panel",
            header { class: "circle-realm-header",
                HelpTip { text: "Circles restrict membership, history, delivery and encryption inside this Realm." }
                div { class: "actions",
                    button {
                        class: "secondary",
                        r#type: "button",
                        disabled: busy(),
                        onclick: move |_| refresh += 1,
                        "Refresh"
                    }
                    button {
                        class: "primary",
                        r#type: "button",
                        "data-testid": "circle-create-open",
                        onclick: move |_| create_open.set(true),
                        "New Circle"
                    }
                }
            }

            if !status().is_empty() {
                div { class: "circle-status", role: "status", "data-testid": "circle-status", "{status}" }
            }

            div { class: "circle-realm-grid",
                nav { class: "circle-list", "aria-label": "Ordinary Circles",
                    if loading() {
                        p { class: "muted", "Loading Circles…" }
                    } else if circles().is_empty() {
                        div { class: "circle-empty",
                            h2 { "No ordinary Circles" }
                            p { class: "muted", "Create a Circle for a smaller collaboration boundary. Agent Sidecars never appear here." }
                        }
                    } else {
                        for circle in circles() {
                            Link {
                                class: if selected_circle_id.as_deref() == Some(circle.circle_id.as_str()) { "circle-list-item is-active" } else { "circle-list-item" },
                                key: "{circle.circle_id}",
                                "data-testid": "circle-list-item",
                                to: Route::CircleDetail {
                                    realm_id: realm_id.clone(),
                                    circle_id: circle.circle_id.to_string(),
                                },
                                div { class: "circle-list-item-head",
                                    strong { "{circle.title}" }
                                    span { class: "pill", "{lifecycle_label(circle.state)}" }
                                }
                                span { class: "muted",
                                    "{circle.display.short_name} · {circle.member_ids.len()} members"
                                }
                                span { class: "muted", "{encryption_label(circle.mls_group_id.as_deref())}" }
                            }
                        }
                    }
                }

                section { class: "circle-detail", "data-testid": "circle-detail",
                    if let Some(circle) = selected {
                        div { class: "circle-detail-heading",
                            div {
                                p { class: "eyebrow", "{circle.display.short_name}" }
                                h2 { "{circle.title}" }
                                if let Some(summary) = circle.summary.as_deref() {
                                    p { class: "muted", "{summary}" }
                                }
                            }
                            span { class: "pill", "{lifecycle_label(circle.state)}" }
                        }
                        div { class: "circle-boundary-grid",
                            div { strong { "Membership" } span {
                                "{circle.member_ids.len()} active members"
                            } }
                            div { strong { "Your access" } span { "{membership_label(circle.viewer_membership)}" } }
                            div { strong { "Join rule" } span { "{circle.join_rule:?}" } }
                            div { strong { "History" } span { "{circle.history_access:?}" } }
                            div { strong { "Directory" } span { "{circle.directory_visibility:?}" } }
                            div { strong { "Encryption" } span { "{encryption_label(circle.mls_group_id.as_deref())}" } }
                        }

                        if circle.mls_group_id.is_none() {
                            div { class: "circle-security-warning",
                                strong { "Not end-to-end encrypted" }
                                p { "This Circle remains a restricted delivery and query boundary until its own MLS genesis is accepted. The server may read plaintext." }
                            }
                        }

                        section { class: "circle-members-section",
                            h3 { "Members" }
                            if circle.member_ids.is_empty() {
                                p { class: "muted", "Member identities are available only to active Circle members." }
                            } else {
                                for member in circle.member_ids.iter() {
                                    div { class: "circle-member-row", key: "{member}",
                                        span { class: "mono", "{member}" }
                                        button {
                                            class: "secondary danger",
                                            r#type: "button",
                                            disabled: busy(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let circle_id = circle.circle_id.to_string();
                                                let member_realm_id = circle.realm_id.to_string();
                                                let principal_id = principal_id.clone();
                                                let actor_id = member.clone();
                                                move |_| {
                                                    busy.set(true);
                                                    let base = base.clone();
                                                    let credential = token();
                                                    let circle_id = circle_id.clone();
                                                    let member_realm_id = member_realm_id.clone();
                                                    let principal_id = principal_id.clone();
                                                    let actor_id = actor_id.clone();
                                                    spawn(async move {
                                                        let outcome = with_authed_api(&base, credential, |api| async move {
                                                            crate::transport::circle::remove_circle_member(
                                                                &api.event_submitter()?,
                                                                &member_realm_id,
                                                                &principal_id,
                                                                &circle_id,
                                                                &actor_id,
                                                            ).await
                                                        }).await;
                                                        match outcome {
                                                            Ok(_) => { status.set("Member access removed".to_owned()); refresh += 1; }
                                                            Err(error) => status.set(format!("Member removal failed: {}", error.display())),
                                                        }
                                                        busy.set(false);
                                                    });
                                                }
                                            },
                                            "Remove"
                                        }
                                    }
                                }
                            }
                            div { class: "circle-member-form",
                                input {
                                    r#type: "text",
                                    value: "{member_actor}",
                                    placeholder: "Complete member ActorId JSON",
                                    "aria-label": "Circle member ActorId",
                                    oninput: move |event| member_actor.set(event.value()),
                                }
                                select {
                                    value: "{member_state}",
                                    "aria-label": "Circle membership state",
                                    onchange: move |event| member_state.set(event.value()),
                                    option { value: "invite", "Invite" }
                                    option { value: "join", "Join" }
                                    option { value: "knock", "Request (knock)" }
                                    option { value: "leave", "Leave" }
                                    option { value: "ban", "Ban" }
                                }
                                button {
                                    class: "secondary",
                                    r#type: "button",
                                    disabled: busy() || member_actor().trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let circle_id = circle.circle_id.to_string();
                                        let member_realm_id = circle.realm_id.to_string();
                                        let principal_id = principal_id.clone();
                                        move |_| {
                                            let Ok(member_id) = serde_json::from_str::<arkret_sdk::ActorId>(member_actor().trim()) else {
                                                status.set("Enter a complete member ActorId including its identity kind and Station when applicable".to_owned());
                                                return;
                                            };
                                            let membership = match member_state().as_str() {
                                                "join" => arkret_sdk::CircleMembership::Join,
                                                "knock" => arkret_sdk::CircleMembership::Knock,
                                                "leave" => arkret_sdk::CircleMembership::Leave,
                                                "ban" => arkret_sdk::CircleMembership::Ban,
                                                _ => arkret_sdk::CircleMembership::Knock,
                                            };
                                            busy.set(true);
                                            let base = base.clone();
                                            let credential = token();
                                            let circle_id = circle_id.clone();
                                            let member_realm_id = member_realm_id.clone();
                                            let principal_id = principal_id.clone();
                                            spawn(async move {
                                                let outcome = with_authed_api(&base, credential, |api| async move {
                                                    crate::transport::circle::add_circle_member(
                                                        &api.event_submitter()?, &member_realm_id, &principal_id, &circle_id, &member_id, membership,
                                                    ).await
                                                }).await;
                                                match outcome {
                                                    Ok(_) => { status.set("Membership updated".to_owned()); member_actor.set(String::new()); refresh += 1; }
                                                    Err(error) => status.set(format!("Membership update failed: {}", error.display())),
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    "Apply"
                                }
                            }
                        }

                        div { class: "actions circle-lifecycle-actions",
                            if circle.state == arkret_sdk::CircleState::Active {
                                button {
                                    class: "secondary",
                                    r#type: "button",
                                    disabled: busy(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let circle_id = circle.circle_id.to_string();
                                        let realm_id = circle.realm_id.to_string();
                                        let principal_id = principal_id.clone();
                                        move |_| {
                                            busy.set(true);
                                            let base = base.clone();
                                            let credential = token();
                                            let circle_id = circle_id.clone();
                                            let realm_id = realm_id.clone();
                                            let principal_id = principal_id.clone();
                                            spawn(async move {
                                                let outcome = with_authed_api(&base, credential, |api| async move {
                                                    crate::transport::circle::archive_circle(&api.event_submitter()?, &realm_id, &principal_id, &circle_id, None).await
                                                }).await;
                                                match outcome {
                                                    Ok(_) => { status.set("Circle archived".to_owned()); refresh += 1; }
                                                    Err(error) => status.set(format!("Archive failed: {}", error.display())),
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    "Archive"
                                }
                            } else if circle.state == arkret_sdk::CircleState::Archived {
                                button {
                                    class: "secondary",
                                    r#type: "button",
                                    disabled: busy(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let circle_id = circle.circle_id.to_string();
                                        let realm_id = circle.realm_id.to_string();
                                        let principal_id = principal_id.clone();
                                        move |_| {
                                            busy.set(true);
                                            let base = base.clone();
                                            let credential = token();
                                            let circle_id = circle_id.clone();
                                            let realm_id = realm_id.clone();
                                            let principal_id = principal_id.clone();
                                            spawn(async move {
                                                let outcome = with_authed_api(&base, credential, |api| async move {
                                                    crate::transport::circle::restore_circle(&api.event_submitter()?, &realm_id, &principal_id, &circle_id, None).await
                                                }).await;
                                                match outcome {
                                                    Ok(_) => { status.set("Circle restored".to_owned()); refresh += 1; }
                                                    Err(error) => status.set(format!("Restore failed: {}", error.display())),
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    "Restore"
                                }
                            }
                        }
                    } else {
                        div { class: "circle-empty",
                            h2 { "Select a Circle" }
                            p { class: "muted", "Review the exact membership and encryption boundary before creating scoped content." }
                        }
                    }
                }
            }

            if create_open() {
                div { class: "discussion-modal-backdrop", "data-testid": "circle-create-modal",
                    div { class: "discussion-modal circle-create-modal",
                        div { class: "discussion-modal-head",
                            h2 { "Create Circle" }
                            button { class: "secondary", r#type: "button", onclick: move |_| create_open.set(false), "Cancel" }
                        }
                        div { class: "workflow-form",
                            label { "Title" }
                            input { r#type: "text", value: "{create_title}", oninput: move |event| create_title.set(event.value()), "data-testid": "circle-create-title" }
                            label { "Summary" }
                            textarea { value: "{create_summary}", oninput: move |event| create_summary.set(event.value()) }
                            div { class: "circle-boundary-preview",
                                strong { "Boundary preview" }
                                p { "Initial member: {principal_id}" }
                                p { "Directory: Circle members only" }
                                p { "Join rule: open to active Realm members" }
                                p { "History: joined members" }
                                p { "Starts as restricted delivery only. E2EE becomes active only after this Circle's own MLS genesis is accepted." }
                            }
                        }
                        div { class: "discussion-modal-actions",
                            button {
                                class: "primary",
                                r#type: "button",
                                disabled: create_disabled,
                                "data-testid": "circle-create-submit",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm_id = realm_id.clone();
                                    let principal_id = principal_id.clone();
                                    move |_| {
                                        let realm_id_text = realm_id.clone();
                                        let Ok(realm_id) = arkret_sdk::RealmId::new(realm_id_text.clone()) else {
                                            status.set("Invalid Realm id".to_owned());
                                            return;
                                        };
                                        let Ok(actor_id) = arkret_sdk::DidCoreId::new(principal_id.clone()) else {
                                            status.set("Invalid account principal id".to_owned());
                                            return;
                                        };
                                        // The Circle id is `retype(create.event_id)`, so the
                                        // Event is authored and signed here and the server
                                        // submits those exact bytes. It cannot name the
                                        // Circle, and it must not sign for us.
                                        let title = create_title().trim().to_owned();
                                        let summary = create_summary().trim().to_owned();
                                        let create_event = match crate::operation::ak_ops::circle_create(
                                            realm_id.as_str(),
                                            &principal_id,
                                            crate::operation::ak_ops::CircleCreateOptions {
                                                title: &title,
                                                summary: Some(&summary),
                                                display: crate::operation::ak_ops::circle_display_from_title(&title),
                                                directory_visibility: arkret_sdk::CircleDirectoryVisibility::Members,
                                                join_rule: arkret_sdk::CircleJoinRule::Public,
                                                history_access: arkret_sdk::HistoryAccess::SinceJoin,
                                            },
                                        )
                                        .and_then(|builder| builder.build_sdk_event("inkson"))
                                        {
                                            Ok(event) => event,
                                            Err(error) => {
                                                status.set(format!("Circle creation failed: {error}"));
                                                return;
                                            }
                                        };
                                        let creator_actor = create_event.actor_id().clone();
                                        let create_operation = create_event;
                                        busy.set(true);
                                        status.set("Creating Circle and establishing initial membership…".to_owned());
                                        let base = base.clone();
                                        let credential = token();
                                        spawn(async move {
                                            let outcome = with_authed_api(&base, credential, |api| async move {
                                                let submitter = api.event_submitter()?;
                                                let request = arkret_sdk::CircleCreateRequestBody {
                                                    create_event: arkret_wire::EventCommitSubmission::new(
                                                        submitter
                                                            .author_for_direct_submission(&create_operation)
                                                            .await?
                                                            .into_event(),
                                                    ),
                                                };
                                                let created = api.http().circle_create(&request).await?;
                                                // The Circle id only exists once the create Event is
                                                // accepted, so the join Event is authored after it.
                                                crate::transport::circle::add_circle_member(
                                                    &submitter,
                                                    created.realm_id.as_str(),
                                                    actor_id.as_str(),
                                                    created.circle_id.as_str(),
                                                    &creator_actor,
                                                    arkret_sdk::CircleMembership::Join,
                                                ).await?;
                                                Ok::<_, anyhow::Error>(created.circle_id.to_string())
                                            }).await;
                                            match outcome {
                                                Ok(circle_id) => {
                                                    create_title.set(String::new());
                                                    create_summary.set(String::new());
                                                    create_open.set(false);
                                                    refresh += 1;
                                                    status.set("Circle created".to_owned());
                                                    let _ = navigator.push(Route::CircleDetail {
                                                        realm_id: realm_id_text,
                                                        circle_id,
                                                    });
                                                }
                                                Err(error) => status.set(format!("Circle creation failed: {}", error.display())),
                                            }
                                            busy.set(false);
                                        });
                                    }
                                },
                                "Create Circle"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::encryption_label;

    #[test]
    fn circle_security_label_follows_accepted_mls_binding() {
        assert_eq!(
            encryption_label(Some("ak:mls_group:accepted")),
            "Independent MLS group · E2EE active"
        );
        assert_eq!(encryption_label(None), "Restricted delivery · not E2EE");
    }
}
