use chrono::{Duration, Utc};
use dioxus::prelude::*;

use crate::local_state::LocalStateStore;
use crate::models::ConsentCellOutcome;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[component]
pub fn ConsentSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = state_store;

    let cells = use_signal(Vec::<ConsentCellOutcome>::new);
    let mut loaded = use_signal(|| false);
    let mut show_form = use_signal(|| false);
    let mut new_scope = use_signal(|| "message".to_owned());
    let mut new_grantee = use_signal(String::new);
    let mut new_ttl = use_signal(|| "30d".to_owned());
    let mut selected_cell_id = use_signal(String::new);
    let mut detail_scope = use_signal(|| "message".to_owned());
    let mut detail_expires_at = use_signal(String::new);
    let mut status = use_signal(String::new);

    {
        let base = base_url();
        let api_token = token();
        use_effect(move || {
            if loaded() {
                return;
            }
            loaded.set(true);
            refresh_consent_cells(base.clone(), api_token.clone(), cells, status);
        });
    }

    rsx! {
        div { class: "event", "data-testid": "consent-settings-panel",
            div { class: "event-head",
                span { "Consent" }
                span { "{cells.read().len()} cells" }
            }

            if cells.read().is_empty() {
                div { class: "event", "data-testid": "consent-grant-empty",
                    div { class: "muted", "No consent cells" }
                }
            } else {
                ul { class: "settings-list",
                    for cell in cells.read().iter().filter(|cell| cell.state == "pending").cloned() {
                        li {
                            class: "event",
                            "data-testid": "consent-pending-row",
                            "data-cell-id": "{cell.cell_id}",
                            div { class: "event-head",
                                span { "pending" }
                                span { class: "mono", title: "{cell.peer_did}", "{short_protocol_id(&cell.peer_did)}" }
                            }
                            div { class: "mono", "{cell.peer_did}" }
                            div { class: "muted", "{cell.scope}" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "consent-detail-button",
                                onclick: {
                                    let cell = cell.clone();
                                    move |_| {
                                        selected_cell_id.set(cell.cell_id.clone());
                                        detail_scope.set(cell.scope.clone());
                                        detail_expires_at.set(
                                            cell.expires_at.clone().unwrap_or_else(|| {
                                                (Utc::now() + Duration::days(30)).to_rfc3339()
                                            }),
                                        );
                                    }
                                },
                                "Details"
                            }
                            if selected_cell_id() == cell.cell_id {
                                div { class: "event", "data-testid": "consent-pending-detail",
                                    div { class: "mono", "{cell.peer_did}" }
                                    select {
                                        "data-testid": "consent-scope-select",
                                        value: "{detail_scope}",
                                        onchange: move |evt| detail_scope.set(evt.value()),
                                        option { value: "invite", "invite" }
                                        option { value: "message", "message" }
                                        option { value: "call", "call" }
                                    }
                                    Input {
                                        "data-testid": "consent-expires-at-input",
                                        value: "{detail_expires_at}",
                                        oninput: move |event: FormEvent| detail_expires_at.set(event.value()),
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "grant-consent-button",
                                        onclick: {
                                            let holder = account_did();
                                            let peer = cell.peer_did.clone();
                                            let base = base_url();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let holder = holder.clone();
                                                let peer = peer.clone();
                                                let scope = detail_scope();
                                                let expires_at = normalize_expires_at(&detail_expires_at());
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, |api| async move {
                                                        api.grant_consent_cell(
                                                            &holder,
                                                            &peer,
                                                            &scope,
                                                            expires_at.as_deref(),
                                                        )
                                                        .await
                                                    })
                                                    .await
                                                    {
                                                        Ok(_) => {
                                                            status.set("granted".to_owned());
                                                            refresh_consent_cells(base, token(), cells, status);
                                                        }
                                                        Err(err) => status.set(format!("grant error {}", err.display())),
                                                    }
                                                });
                                            }
                                        },
                                        "Grant"
                                    }
                                }
                            }
                        }
                    }
                    for cell in cells.read().iter().filter(|cell| cell.state == "granted").cloned() {
                        {
                            let peer_label = short_protocol_id(&cell.peer_did);
                            let expiry_label = cell
                                .expires_at
                                .clone()
                                .unwrap_or_else(|| "no expiry".to_owned());
                            rsx! {
                                li {
                                    class: "event",
                                    "data-testid": "consent-granted-row",
                                    "data-cell-id": "{cell.cell_id}",
                                    div { class: "event-head",
                                        span { "{cell.scope}" }
                                        span { class: "mono", title: "{cell.peer_did}", "{peer_label}" }
                                    }
                                    div { class: "mono", "{cell.peer_did}" }
                                    div { class: "muted", "{expiry_label}" }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "revoke-consent-button",
                                        onclick: {
                                            let holder = account_did();
                                            let peer = cell.peer_did.clone();
                                            let scope = cell.scope.clone();
                                            let base = base_url();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let holder = holder.clone();
                                                let peer = peer.clone();
                                                let scope = scope.clone();
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, |api| async move {
                                                        api.revoke_consent_cell(&holder, &peer, &scope).await
                                                    })
                                                    .await
                                                    {
                                                        Ok(_) => {
                                                            status.set("revoked".to_owned());
                                                            refresh_consent_cells(base, token(), cells, status);
                                                        }
                                                        Err(err) => status.set(format!("revoke error {}", err.display())),
                                                    }
                                                });
                                            }
                                        },
                                        "Revoke"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "consent-new-grant-button",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "Cancel" } else { "New grant" }
                }
            }

            if show_form() {
                div { class: "event",
                    Input {
                        "data-testid": "consent-new-grant-scope-input",
                        value: "{new_scope}",
                        oninput: move |event: FormEvent| new_scope.set(event.value()),
                    }
                    Input {
                        "data-testid": "consent-new-grant-grantee-input",
                        value: "{new_grantee}",
                        placeholder: "did:web:peer.example",
                        oninput: move |event: FormEvent| new_grantee.set(event.value()),
                    }
                    Input {
                        "data-testid": "consent-new-grant-ttl-input",
                        value: "{new_ttl}",
                        oninput: move |event: FormEvent| new_ttl.set(event.value()),
                    }
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "consent-new-grant-submit-button",
                        disabled: new_grantee.read().trim().is_empty(),
                        onclick: {
                            let holder = account_did();
                            let base = base_url();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                let holder = holder.clone();
                                let peer = new_grantee().trim().to_owned();
                                let scope = new_scope().trim().to_owned();
                                let expires_at = normalize_expires_at(&new_ttl());
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.grant_consent_cell(
                                            &holder,
                                            &peer,
                                            &scope,
                                            expires_at.as_deref(),
                                        )
                                        .await
                                    })
                                    .await
                                    {
                                        Ok(_) => {
                                            show_form.set(false);
                                            new_grantee.set(String::new());
                                            status.set("granted".to_owned());
                                            refresh_consent_cells(base, token(), cells, status);
                                        }
                                        Err(err) => status.set(format!("grant error {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Submit"
                    }
                }
            }

            if !status.read().is_empty() {
                div { class: "muted", "data-testid": "write-status", "{status}" }
                div { class: "muted", "data-testid": "consent-new-grant-status", "{status}" }
            }
        }
    }
}

fn refresh_consent_cells(
    base_url: String,
    api_token: String,
    mut cells: Signal<Vec<ConsentCellOutcome>>,
    mut status: Signal<String>,
) {
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.list_consent_cells().await
        })
        .await
        {
            Ok(response) => cells.set(response.cells),
            Err(err) => status.set(format!("load error {}", err.display())),
        }
    });
}

fn normalize_expires_at(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(days) = trimmed
        .strip_suffix('d')
        .and_then(|value| value.parse::<i64>().ok())
    {
        return Some((Utc::now() + Duration::days(days)).to_rfc3339());
    }
    if let Some(hours) = trimmed
        .strip_suffix('h')
        .and_then(|value| value.parse::<i64>().ok())
    {
        return Some((Utc::now() + Duration::hours(hours)).to_rfc3339());
    }
    Some(trimmed.to_owned())
}
