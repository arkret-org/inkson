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

fn lifecycle_label(state: arkret_sdk::CircleState) -> String {
    match state {
        arkret_sdk::CircleState::Active => crate::i18n::tr("circles.page.state_active"),
        arkret_sdk::CircleState::Archived => crate::i18n::tr("circles.page.state_archived"),
        arkret_sdk::CircleState::Tombstoned => crate::i18n::tr("circles.page.state_tombstoned"),
    }
}

fn membership_label(state: Option<arkret_sdk::CircleMembership>) -> String {
    match state {
        Some(arkret_sdk::CircleMembership::Join) => crate::i18n::tr("circles.page.membership_join"),
        Some(arkret_sdk::CircleMembership::Knock) => {
            crate::i18n::tr("circles.page.membership_knock")
        }
        Some(arkret_sdk::CircleMembership::Leave) => {
            crate::i18n::tr("circles.page.membership_leave")
        }
        Some(arkret_sdk::CircleMembership::Ban) => crate::i18n::tr("circles.page.membership_ban"),
        None => crate::i18n::tr("circles.page.membership_viewer"),
    }
}

fn encryption_label(mls_group_id: Option<&str>) -> String {
    if mls_group_id.is_some() {
        crate::i18n::tr("circles.page.encrypted")
    } else {
        crate::i18n::tr("circles.page.unencrypted")
    }
}

fn initial_member_label(principal: &str) -> String {
    crate::i18n::tr_args(
        "circles.page.initial_member",
        &[("member", principal.to_owned())],
    )
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
                h1 { {crate::i18n::tr("circles.page.heading")} }
                HelpTip { text: crate::i18n::tr("circles.page.help") }
                div { class: "actions",
                    button {
                        class: "secondary",
                        r#type: "button",
                        disabled: busy(),
                        onclick: move |_| refresh += 1,
                        {crate::i18n::tr("common.refresh")}
                    }
                    button {
                        class: "primary",
                        r#type: "button",
                        "data-testid": "circle-create-open",
                        onclick: move |_| create_open.set(true),
                        {crate::i18n::tr("circles.page.new")}
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
                nav { class: "circle-list", "aria-label": crate::i18n::tr("circles.page.nav_label"),
                    if loading() {
                        p { class: "muted", {crate::i18n::tr("circles.page.loading")} }
                    } else if circles().is_empty() && previews().is_empty() {
                        div { class: "circle-empty",
                            h2 { {crate::i18n::tr("circles.page.empty")} }
                            p { class: "muted", {crate::i18n::tr("circles.page.empty_help")} }
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
                                    {crate::i18n::tr_args("circles.page.member_count", &[("count", circle.member_ids.len().to_string())])}
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
                                    strong { {crate::i18n::tr("circles.page.preview")} }
                                    span { class: "pill", {crate::i18n::tr("circles.page.directory")} }
                                }
                                CircleIdentityBadge { color: preview.display.color_token, symbol: preview.display.symbol.clone() }
                                span { class: "muted", {crate::i18n::tr_args("circles.page.preview_count", &[("count", preview_member_count(preview.member_count_bucket).to_owned()), ("rule", format!("{:?}", preview.join_rule))])} }
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
                            div { strong { {crate::i18n::tr("circles.page.membership")} } span {
                                {crate::i18n::tr_args("circles.page.active_count", &[("count", circle.member_ids.len().to_string())])}
                            } }
                            div { strong { {crate::i18n::tr("circles.page.your_access")} } span { "{membership_label(circle.viewer_membership)}" } }
                            div { strong { {crate::i18n::tr("circles.page.join_rule")} } span { "{circle.join_rule:?}" } }
                            div { strong { {crate::i18n::tr("circles.page.history")} } span { "{circle.history_access:?}" } }
                            div { strong { {crate::i18n::tr("circles.page.directory")} } span { "{circle.directory_visibility:?}" } }
                            div { strong { {crate::i18n::tr("circles.page.encryption")} } span { "{encryption_label(circle.mls_group_id.as_deref())}" } }
                        }

                        if circle.mls_group_id.is_none() {
                            div { class: "circle-security-warning",
                                strong { {crate::i18n::tr("circles.page.not_encrypted")} }
                                p { {crate::i18n::tr("circles.page.plaintext_warning")} }
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
                            h3 { {crate::i18n::tr("circles.page.members")} }
                            if circle.member_ids.is_empty() {
                                p { class: "muted", {crate::i18n::tr("circles.page.members_private")} }
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
                                            {crate::i18n::tr("circles.page.remove")}
                                        }
                                    }
                                }
                            }
                            div { class: "circle-member-form",
                                input {
                                    r#type: "text",
                                    value: "{member_actor}",
                                    placeholder: crate::i18n::tr("circles.page.actor_placeholder"),
                                    "aria-label": crate::i18n::tr("circles.page.actor_label"),
                                    oninput: move |event| member_actor.set(event.value()),
                                }
                                select {
                                    value: "{member_state}",
                                    "aria-label": crate::i18n::tr("circles.page.membership_state"),
                                    onchange: move |event| member_state.set(event.value()),

                                    option { value: "join", {crate::i18n::tr("circles.page.add_member")} }
                                    if circle.join_rule == arkret_sdk::CircleJoinRule::Knock {
                                        option { value: "knock", {crate::i18n::tr("circles.page.request")} }
                                    }
                                    option { value: "leave", {crate::i18n::tr("circles.page.leave")} }
                                    option { value: "ban", {crate::i18n::tr("circles.page.ban")} }
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
                                    {crate::i18n::tr("circles.page.apply")}
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
                                    {crate::i18n::tr("circles.page.archive")}
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
                                    {crate::i18n::tr("circles.page.restore")}
                                }
                            }
                        }
                    } else if let Some(preview) = selected_preview {
                        div { class: "circle-detail-heading",
                            div {
                                p { class: "eyebrow", {crate::i18n::tr("circles.page.directory_preview")} }
                                h2 { {crate::i18n::tr("circles.page.preview")} }
                                p { class: "muted", {crate::i18n::tr("circles.page.preview_private")} }
                            }
                        }
                        CircleSelfMembership {
                            realm_id: preview.realm_id.to_string(),
                            circle_id: preview.circle_id.to_string(), principal_id: principal_id.clone(),
                            join_rule: preview.join_rule, membership: None, terminal: false,
                            token, busy, refresh, status,
                        }
                        div { class: "circle-boundary-grid",
                            div { strong { {crate::i18n::tr("circles.page.members")} } span { {crate::i18n::tr_args("circles.page.approximate_count", &[("count", preview_member_count(preview.member_count_bucket).to_owned())])} } }
                            div { strong { {crate::i18n::tr("circles.page.join_rule")} } span { "{preview.join_rule:?}" } }
                        }
                    } else {
                        div { class: "circle-empty",
                            h2 { {crate::i18n::tr("circles.page.select")} }
                            p { class: "muted", {crate::i18n::tr("circles.page.select_help")} }
                        }
                    }
                }
            }

            if create_open() {
                div { class: "discussion-modal-backdrop", "data-testid": "circle-create-modal",
                    div { class: "discussion-modal circle-create-modal",
                        div { class: "discussion-modal-head",
                            h2 { {crate::i18n::tr("circles.page.create")} }
                            button { class: "secondary", r#type: "button", onclick: move |_| create_open.set(false), {crate::i18n::tr("common.cancel")} }
                        }
                        div { class: "workflow-form",
                            label { {crate::i18n::tr("circles.page.title")} }
                            input { r#type: "text", value: "{create_title}", oninput: move |event| create_title.set(event.value()), "data-testid": "circle-create-title" }
                            label { {crate::i18n::tr("circles.page.short_name")} }
                            input {
                                value: "{create_short_name}", "aria-label": crate::i18n::tr("circles.page.short_name_label"),
                                "data-testid": "circle-create-short-name",
                                oninput: move |event| create_short_name.set(event.value()),
                            }
                            label { {crate::i18n::tr("circles.page.summary")} }
                            textarea { value: "{create_summary}", oninput: move |event| create_summary.set(event.value()) }
                            CirclePolicyFields { visibility: create_visibility, join_rule: create_join_rule }
                            label { {crate::i18n::tr("circles.page.history")} }
                            select {
                                "aria-label": crate::i18n::tr("circles.page.history_label"), value: if create_history() == arkret_sdk::HistoryAccess::SinceJoin { "since_join" } else { "all_history_for_current_members" },
                                onchange: move |event| create_history.set(if event.value() == "since_join" { arkret_sdk::HistoryAccess::SinceJoin } else { arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers }),
                                option { value: "since_join", {crate::i18n::tr("circles.page.since_join")} }
                                option { value: "all_history_for_current_members", {crate::i18n::tr("circles.page.all_history")} }
                            }
                            label {
                                input { r#type: "checkbox", checked: create_encrypted(),
                                    "data-testid": "circle-create-encrypted",
                                    onchange: move |event| create_encrypted.set(event.checked()) }
                                {crate::i18n::tr("circles.page.e2ee")}
                            }
                            div { class: "circle-boundary-preview",
                                strong { {crate::i18n::tr("circles.page.boundary_preview")} }
                                p { {initial_member_label(&principal_id)} }
                                p { {crate::i18n::tr_args("circles.page.directory_value", &[("value", format!("{:?}", create_visibility()))])} }
                                p { {crate::i18n::tr_args("circles.page.join_rule_value", &[("value", format!("{:?}", create_join_rule()))])} }
                                p { {crate::i18n::tr_args("circles.page.history_value", &[("value", format!("{:?}", create_history()))])} }
                                p { {crate::i18n::tr("circles.page.boundary_help")} }
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
                                {crate::i18n::tr("circles.page.create")}
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

#[cfg(test)]
mod locale_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::i18n::{I18nSignal, UiLocale};

    type LocaleHandle = Rc<RefCell<(Option<I18nSignal>, usize)>>;

    fn retained_circle_labels(handle: LocaleHandle) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        handle.borrow_mut().0 = Some(locale);
        let original = use_signal(move || {
            handle.borrow_mut().1 += 1;
            "circles.page.membership_join {member} 原文".to_owned()
        });
        let raw = original();
        // Render the same production helpers as the Circle list and create preview.
        // No session-dependent controls or authoring lifecycle are mounted here.
        rsx! {
            div {
                for state in [arkret_sdk::CircleState::Active, arkret_sdk::CircleState::Archived, arkret_sdk::CircleState::Tombstoned] {
                    p { {lifecycle_label(state)} }
                }
                for membership in [Some(arkret_sdk::CircleMembership::Join), Some(arkret_sdk::CircleMembership::Knock), Some(arkret_sdk::CircleMembership::Leave), Some(arkret_sdk::CircleMembership::Ban), None] {
                    p { {membership_label(membership)} }
                }
                p { {encryption_label(Some(&raw))} }
                p { {encryption_label(None)} }
                p { {initial_member_label(&raw)} }
                p { "{raw}" }
            }
        }
    }

    fn apply_text_edits(
        text: &mut BTreeMap<usize, String>,
        edits: dioxus::core::Mutations,
    ) -> usize {
        let mut changed = 0;
        for edit in edits.edits {
            match edit {
                dioxus::core::Mutation::CreateTextNode { id, value }
                | dioxus::core::Mutation::SetText { id, value } => {
                    text.insert(id.0, value);
                    changed += 1;
                }
                _ => {}
            }
        }
        changed
    }

    #[test]
    fn retained_circle_labels_rerender_typed_boundaries_without_translating_original_parameters() {
        let handle = Rc::new(RefCell::new((None, 0)));
        let mut dom = VirtualDom::new_with_props(retained_circle_labels, handle.clone());
        let mut text = BTreeMap::new();
        assert!(apply_text_edits(&mut text, dom.rebuild_to_vec()) > 0);
        let english = text.clone();
        let raw = "circles.page.membership_join {member} 原文";
        for expected in [
            "Active",
            "Archived",
            "Tombstoned",
            "Member",
            "Requested",
            "Left",
            "Banned",
            "Directory viewer",
            "Independent MLS group · E2EE active",
            "Restricted delivery · not E2EE",
        ] {
            assert!(
                text.values().any(|value| value == expected),
                "missing label: {expected}"
            );
        }
        assert!(
            text.values()
                .any(|value| value == &format!("Initial member: {raw}"))
        );
        let mut locale = handle.borrow().0.expect("Circle labels provide locale");
        for language in [UiLocale::Zh, UiLocale::En] {
            dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
            assert!(apply_text_edits(&mut text, dom.render_immediate_to_vec()) > 0);
            assert!(text.values().any(|value| value == raw));
            assert_eq!(
                handle.borrow().1,
                1,
                "the original signal must survive locale changes"
            );
            if language == UiLocale::Zh {
                for expected in [
                    "活跃",
                    "已归档",
                    "已永久停用",
                    "成员",
                    "已申请",
                    "已退出",
                    "已禁止加入",
                    "目录浏览者",
                    "独立 MLS 群组 · 已启用端到端加密",
                    "限制投递范围 · 未启用端到端加密",
                ] {
                    assert!(
                        text.values().any(|value| value == expected),
                        "missing label: {expected}"
                    );
                }
                assert!(
                    text.values()
                        .any(|value| value == &format!("初始成员：{raw}"))
                );
            } else {
                assert_eq!(text, english);
            }
        }
    }
}
