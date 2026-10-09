use dioxus::prelude::*;
use dioxus_router::Link;

mod controls;

use controls::{CircleEditForm, CirclePolicyFields, CircleSelfMembership, CircleTerminalActions};

use crate::components::{CircleIdentityBadge, HelpTip};
use crate::routes::Route;
use crate::transport::auth::with_authed_api;

fn valid_short_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=24).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b' ' | b'_' | b'-'))
}

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

fn preview_member_count(bucket: arkret_sdk::CircleMemberCountBucket) -> &'static str {
    use arkret_sdk::CircleMemberCountBucket::*;
    match bucket {
        Zero => "0",
        One => "1",
        TwoToThree => "2–3",
        FourToSeven => "4–7",
        EightToFifteen => "8–15",
        SixteenToThirtyOne => "16–31",
        ThirtyTwoToSixtyThree => "32–63",
        SixtyFourToOneHundredTwentySeven => "64–127",
        OneHundredTwentyEightPlus => "128+",
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
    let session = crate::app::SessionContext::get();
    let navigator = dioxus_router::hooks::use_navigator();
    let mut circles = use_signal(Vec::<arkret_sdk::CircleView>::new);
    let mut previews = use_signal(Vec::<arkret_sdk::CirclePreview>::new);
    let mut loading = use_signal(|| true);
    let mut status = use_signal(String::new);
    let mut refresh = use_signal(|| 0_u64);
    let mut create_open = use_signal(|| false);
    let mut create_title = use_signal(String::new);
    let mut create_summary = use_signal(String::new);
    let mut create_encrypted = use_signal(|| false);
    let mut create_short_name = use_signal(String::new);
    let create_visibility = use_signal(|| arkret_sdk::CircleDirectoryVisibility::Members);
    let create_join_rule = use_signal(|| arkret_sdk::CircleJoinRule::Public);
    let mut create_history = use_signal(|| arkret_sdk::HistoryAccess::SinceJoin);
    let mut member_actor = use_signal(String::new);
    let mut member_state = use_signal(|| "join".to_owned());
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
                        let (full, directory) = crate::circle::split_ordinary_circle_reads(list);
                        circles.set(full);
                        previews.set(directory);
                    }
                    Err(error) => {
                        circles.set(Vec::new());
                        previews.set(Vec::new());
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
    let selected_preview = selected_circle_id.as_deref().and_then(|id| {
        previews()
            .into_iter()
            .find(|preview| preview.circle_id.as_str() == id)
    });
    let create_disabled = busy()
        || create_title().trim().is_empty()
        || (!create_short_name().trim().is_empty()
            && !valid_short_name(create_short_name().trim()));

    rsx! {
        main { class: "circle-realm", "data-testid": "circles-panel",
            header { class: "circle-realm-header",
                h1 { "Circles" }
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

            if let Some(circle_id) = selected_circle_id.clone() {
                crate::components::mls_creator_retry::CreatorMlsRetry {
                    key: "{circle_id}",
                    realm_id: realm_id.clone(), circle_id,
                    refresh_hint: refresh().to_string(), token,
                }
            }

            div { class: "circle-realm-grid",
                nav { class: "circle-list", "aria-label": "Ordinary Circles",
                    if loading() {
                        p { class: "muted", "Loading Circles…" }
                    } else if circles().is_empty() && previews().is_empty() {
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
                                    CircleIdentityBadge { color: circle.display.color_token, symbol: circle.display.symbol.clone(), short_name: circle.display.short_name.clone() }
                                    " · {circle.member_ids.len()} members"
                                }
                                span { class: "muted", "{encryption_label(circle.mls_group_id.as_deref())}" }
                            }
                        }
                        for preview in previews() {
                            Link {
                                class: if selected_circle_id.as_deref() == Some(preview.circle_id.as_str()) { "circle-list-item is-active" } else { "circle-list-item" },
                                key: "{preview.circle_id}",
                                "data-testid": "circle-preview-item",
                                to: Route::CircleDetail {
                                    realm_id: realm_id.clone(),
                                    circle_id: preview.circle_id.to_string(),
                                },
                                div { class: "circle-list-item-head",
                                    strong { "Circle preview" }
                                    span { class: "pill", "Directory" }
                                }
                                CircleIdentityBadge { color: preview.display.color_token, symbol: preview.display.symbol.clone() }
                                span { class: "muted", "{preview_member_count(preview.member_count_bucket)} members · {preview.join_rule:?}" }
                            }
                        }
                    }
                }

                section { class: "circle-detail", "data-testid": "circle-detail",
                    if let Some(circle) = selected {
                        div { class: "circle-detail-heading",
                            div {
                                CircleIdentityBadge { color: circle.display.color_token, symbol: circle.display.symbol.clone(), short_name: circle.display.short_name.clone() }
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

                        CircleSelfMembership {
                            realm_id: circle.realm_id.to_string(),
                            circle_id: circle.circle_id.to_string(), principal_id: principal_id.clone(),
                            join_rule: circle.join_rule, membership: circle.viewer_membership,
                            terminal: circle.state == arkret_sdk::CircleState::Tombstoned,
                            token, busy, refresh, status,
                        }
                        if circle.state == arkret_sdk::CircleState::Active {
                            CircleEditForm {
                                key: "edit-{circle.circle_id}-{refresh}", realm_id: circle.realm_id.to_string(), circle_id: circle.circle_id.to_string(),
                                initial_title: circle.title.clone(), initial_summary: circle.summary.clone(), display: circle.display.clone(),
                                initial_visibility: circle.directory_visibility, initial_join_rule: circle.join_rule,
                                principal_id: principal_id.clone(), token, busy, refresh, status,
                            }
                        }
                        CircleTerminalActions {
                            realm_id: circle.realm_id.to_string(), circle_id: circle.circle_id.to_string(),
                            state: circle.state, history_access: circle.history_access,
                            principal_id: principal_id.clone(), token, busy, refresh, status,
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
                                            disabled: busy() || circle.state == arkret_sdk::CircleState::Tombstoned,
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

                                    option { value: "join", "Add member" }
                                    if circle.join_rule == arkret_sdk::CircleJoinRule::Knock {
                                        option { value: "knock", "Request (knock)" }
                                    }
                                    option { value: "leave", "Leave" }
                                    option { value: "ban", "Ban" }
                                }
                                button {
                                    class: "secondary",
                                    r#type: "button",
                                    disabled: busy() || circle.state == arkret_sdk::CircleState::Tombstoned || member_actor().trim().is_empty(),
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
                                                _ => {
                                                    status.set("Choose a valid membership transition".to_owned());
                                                    return;
                                                },
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
                    } else if let Some(preview) = selected_preview {
                        div { class: "circle-detail-heading",
                            div {
                                p { class: "eyebrow", "Directory preview" }
                                h2 { "Circle preview" }
                                p { class: "muted", "Private details are visible after joining this Circle." }
                            }
                        }
                        CircleSelfMembership {
                            realm_id: preview.realm_id.to_string(),
                            circle_id: preview.circle_id.to_string(), principal_id: principal_id.clone(),
                            join_rule: preview.join_rule, membership: None, terminal: false,
                            token, busy, refresh, status,
                        }
                        div { class: "circle-boundary-grid",
                            div { strong { "Members" } span { "{preview_member_count(preview.member_count_bucket)} (approximate)" } }
                            div { strong { "Join rule" } span { "{preview.join_rule:?}" } }
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
                            label { "Short name (ASCII, unique in this Realm)" }
                            input {
                                value: "{create_short_name}", "aria-label": "Circle short name",
                                "data-testid": "circle-create-short-name",
                                oninput: move |event| create_short_name.set(event.value()),
                            }
                            label { "Summary" }
                            textarea { value: "{create_summary}", oninput: move |event| create_summary.set(event.value()) }
                            CirclePolicyFields { visibility: create_visibility, join_rule: create_join_rule }
                            label { "History" }
                            select {
                                "aria-label": "Circle history", value: if create_history() == arkret_sdk::HistoryAccess::SinceJoin { "since_join" } else { "all_history_for_current_members" },
                                onchange: move |event| create_history.set(if event.value() == "since_join" { arkret_sdk::HistoryAccess::SinceJoin } else { arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers }),
                                option { value: "since_join", "Since joining" }
                                option { value: "all_history_for_current_members", "All history for current members" }
                            }
                            label {
                                input { r#type: "checkbox", checked: create_encrypted(),
                                    "data-testid": "circle-create-encrypted",
                                    onchange: move |event| create_encrypted.set(event.checked()) }
                                "End-to-end encryption"
                            }
                            div { class: "circle-boundary-preview",
                                strong { "Boundary preview" }
                                p { "Initial member: {principal_id}" }
                                p { "Directory: {create_visibility():?}" }
                                p { "Join rule: {create_join_rule():?}" }
                                p { "History: {create_history():?}" }
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
                                        let mut display = crate::operation::ak_ops::circle_display_from_title(&title);
                                        if !create_short_name().trim().is_empty() {
                                            display.short_name = create_short_name().trim().to_owned();
                                        }
                                        let create_event = match crate::operation::ak_ops::circle_create(
                                            realm_id.as_str(),
                                            &principal_id,
                                            crate::operation::ak_ops::CircleCreateOptions {
                                                title: &title,
                                                summary: Some(&summary),
                                                display,
                                                directory_visibility: create_visibility(),
                                                join_rule: create_join_rule(),
                                                history_access: create_history(),
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
                                        let encrypted = create_encrypted();
                                        let account = session.active_account();
                                        let state_store = crate::app::runtime_adapter::state_store_handle(session.state_store);
                                        busy.set(true);
                                        status.set("Creating Circle and establishing initial membership…".to_owned());
                                        let base = base.clone();
                                        let credential = token();
                                        spawn(async move {
                                            let outcome = with_authed_api(&base, credential, |api| async move {
                                                let submitter = api.event_submitter()?;
                                                if encrypted {
                                                    let account = account.ok_or_else(|| anyhow::anyhow!("encrypted Circle requires an active account"))?;
                                                    let circle_id = submitter.submit_circle_creator_durable(&create_operation, &account.device_id).await?;
                                                    let scope = arkret_sdk::ScopeRef::Circle { realm_id: realm_id.clone(), circle_id: circle_id.clone() };
                                                    // The committed intent remains recoverable even if this
                                                    // foreground task or its response disappears.
                                                    crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(
                                                        &api, &state_store, &scope, &account.authority, &account.device_id, false,
                                                    ).await.map_err(anyhow::Error::msg)?;
                                                    return Ok::<_, anyhow::Error>(circle_id.to_string());
                                                }
                                                let parent_revision = submitter
                                                    .read_parent_membership_revision(&realm_id, &creator_actor)
                                                    .await?;
                                                let request = arkret_sdk::CircleCreateRequestBody {
                                                    create_event: arkret_wire::EventAdmissionSubmission::new(
                                                        submitter
                                                            .author_for_direct_submission(&create_operation)
                                                            .await?
                                                            .into_event(),
                                                    ),
                                                };
                                                let created = api.http().circle_create(&request).await?;
                                                // The Circle id only exists once the create Event is
                                                // accepted, so the join Event is authored after it.
                                                crate::transport::circle::submit_circle_member_with_parent_revision(
                                                    &submitter,
                                                    created.realm_id.as_str(),
                                                    actor_id.as_str(),
                                                    created.circle_id.as_str(),
                                                    &creator_actor,
                                                    arkret_sdk::CircleMembership::Join,
                                                    Some(parent_revision),
                                                ).await?;
                                                Ok::<_, anyhow::Error>(created.circle_id.to_string())
                                            }).await;
                                            match outcome {
                                                Ok(circle_id) => {
                                                    create_title.set(String::new());
                                                    create_summary.set(String::new());
                                                    create_short_name.set(String::new());
                                                    create_encrypted.set(false);
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
    use super::{encryption_label, valid_short_name};

    #[test]
    fn circle_short_name_validation_matches_registered_ascii_boundary() {
        for value in ["Ops", "A_1-x", "A12345678901234567890123"] {
            assert!(valid_short_name(value));
        }
        for value in ["", "ops", "运维", "A!", "A1234567890123456789012345"] {
            assert!(!valid_short_name(value));
        }
    }

    #[test]
    fn circle_security_label_follows_accepted_mls_binding() {
        assert_eq!(
            encryption_label(Some("ak:mls_group:accepted")),
            "Independent MLS group · E2EE active"
        );
        assert_eq!(encryption_label(None), "Restricted delivery · not E2EE");
    }
}
