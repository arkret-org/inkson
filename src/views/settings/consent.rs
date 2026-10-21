//! Complete exact-peer Consent editing with an authenticated read and explicit diff.

use dioxus::prelude::*;

use crate::i18n::tr;
use crate::transport::account::ConsentEdit;
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;

fn consent_peer_label(peer: &arkret_sdk::ConsentPeer) -> String {
    let arkret_sdk::ConsentPeer::Actor { actor_id } = peer;
    match actor_id {
        arkret_sdk::ActorId::Realm { realm_actor_id } => realm_actor_id.to_string(),
        arkret_sdk::ActorId::Account { account_id } => {
            format!("{} @ {}", account_id.principal_id, account_id.station_id)
        }
        arkret_sdk::ActorId::Service { service_id } => crate::i18n::tr_args(
            "consent.peer_service",
            &[("service", service_id.to_string())],
        ),
    }
}

fn parse_peer(principal: &str, station: &str) -> anyhow::Result<arkret_sdk::ConsentPeer> {
    if principal.trim().starts_with('{') {
        Ok(serde_json::from_str(principal)?)
    } else {
        crate::operation::ak_ops::consent_actor_peer(principal, Some(station))
    }
}

fn scope_label(scope: &str) -> String {
    tr(match scope {
        "invite" => "consent.scope.invite",
        "voice_call" => "consent.scope.voice_call",
        "video_call" => "consent.scope.video_call",
        "presence" => "consent.scope.presence",
        _ => "consent.scope.unknown",
    })
}

/// A toggle preserves every unedited entry, including its optional-member presence.
fn toggle_scope(
    raw: &str,
    scope: arkret_sdk::ConsentScope,
    enabled: bool,
) -> anyhow::Result<String> {
    let mut permissions: Vec<arkret_sdk::ConsentPermission> = serde_json::from_str(raw)?;
    if enabled {
        if !permissions.iter().any(|p| p.consent_scope == scope) {
            permissions.push(serde_json::from_value(
                serde_json::json!({"consent_scope": scope}),
            )?);
        }
    } else {
        permissions.retain(|p| p.consent_scope != scope);
    }
    permissions.sort_by_key(|p| match p.consent_scope {
        arkret_sdk::ConsentScope::Invite => 0,
        arkret_sdk::ConsentScope::VoiceCall => 1,
        arkret_sdk::ConsentScope::VideoCall => 2,
        arkret_sdk::ConsentScope::Presence => 3,
    });
    Ok(serde_json::to_string_pretty(&permissions)?)
}

#[component]
pub fn ConsentSettingsPanel(principal_id: Signal<String>, token: Signal<String>) -> Element {
    let session = crate::app::SessionContext::get();
    let active_account = session.active_account;
    let generation = session.session_generation;
    let mut rows = use_signal(Vec::<arkret_sdk::ConsentView>::new);
    let mut status = use_signal(String::new);
    let mut load_error = use_signal(|| None::<String>);
    let mut loaded = use_signal(|| false);
    let mut reload = use_signal(|| 0_u64);
    let mut busy = use_signal(|| false);
    let mut peer_principal = use_signal(String::new);
    let mut peer_station = use_signal(String::new);
    let mut edit = use_signal(|| None::<ConsentEdit>);
    let mut original = use_signal(String::new);
    let mut draft = use_signal(|| "[]".to_owned());
    let mut preview = use_signal(|| None::<arkret_sdk::ConsentReplacePayload>);
    let mut request_scope = use_signal(|| "voice_call".to_owned());
    let request_scope_selected = use_memo(move || Some(request_scope()));
    let mut request_holder = use_signal(String::new);
    let mut request_station = use_signal(String::new);
    let mut load_sequence = use_signal(|| 0_u64);
    let mut editing_session = use_signal(|| None::<(arkret_sdk::AccountId, u64)>);

    use_effect(move || {
        let _ = reload();
        let _ = principal_id();
        let captured_generation = generation();
        let account = active_account();
        let current_session = account
            .as_ref()
            .map(|account| (account.authority.clone(), captured_generation));
        if *editing_session.peek() != current_session {
            peer_principal.set(String::new());
            peer_station.set(String::new());
            request_holder.set(String::new());
            request_station.set(String::new());
            editing_session.set(current_session);
        }
        let sequence = load_sequence.peek().wrapping_add(1);
        load_sequence.set(sequence);
        rows.set(Vec::new());
        load_error.set(None);
        loaded.set(false);
        edit.set(None);
        preview.set(None);
        original.set(String::new());
        draft.set("[]".to_owned());
        busy.set(false);
        status.set(String::new());
        let Some(account) = account else {
            return;
        };
        let api_token = token();
        spawn(async move {
            let result =
                with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                    let list = crate::transport::account::consent_cells(&http).await?;
                    list.validate()?;
                    Ok(list)
                })
                .await;
            if generation() != captured_generation || *load_sequence.peek() != sequence {
                return;
            }
            match result {
                Ok(list) => {
                    rows.set(list.consents);
                    loaded.set(true);
                }
                Err(error) => load_error.set(Some(error.display())),
            }
        });
    });

    let selected_permissions: Vec<arkret_sdk::ConsentPermission> =
        serde_json::from_str(&draft()).unwrap_or_default();
    let preview_text = preview()
        .as_ref()
        .map(|p| serde_json::to_string_pretty(&p.permissions).unwrap_or_default())
        .unwrap_or_default();
    let expected_text = edit()
        .as_ref()
        .and_then(|e| e.expected_current().ok())
        .map(|expected| {
            tr(match expected {
                arkret_sdk::ConsentExpectedCurrent::NeverWritten => "consent.never_written",
                arkret_sdk::ConsentExpectedCurrent::Present { .. } => "consent.existing",
            })
        })
        .unwrap_or_default();
    rsx! {
        div { class: "timeline", "data-testid": "consent-settings-panel",
            div { class: "event",
                div { class: "event-head", span { {tr("consent.title")} } }
                p { {tr("consent.edit_intro")} }
                Button { variant: ButtonVariant::Secondary, disabled: busy(),
                    "data-testid": "consent-retry-button", onclick: move |_| reload.set(reload() + 1),
                    {tr("common.refresh")}
                }
            }
            if let Some(error) = load_error() {
                div { class: "event error-banner", "data-testid": "consent-load-error",
                    {crate::i18n::tr_args("consent.load_failed", &[("error", error)])}
                }
            }
            if loaded() && rows().is_empty() {
                div { class: "muted", "data-testid": "consent-peer-empty", {tr("consent.empty")} }
            }
            for row in rows().iter() {
                div { class: "event", "data-testid": "consent-peer-row",
                    "data-peer": serde_json::to_string(&row.peer).unwrap_or_default(),
                    strong { {consent_peer_label(&row.peer)} }
                    div { class: "muted",
                        if row.permission_scopes.is_empty() { {tr("consent.closed")} }
                        for scope in &row.permission_scopes { span { "{scope_label(scope.as_str())} " } }
                    }
                    Button { variant: ButtonVariant::Secondary, disabled: busy(),
                        onclick: {
                            let peer = row.peer.clone();
                            move |_| {
                                if let arkret_sdk::ConsentPeer::Actor { actor_id: arkret_sdk::ActorId::Account { account_id } } = &peer {
                                    peer_principal.set(account_id.principal_id.to_string());
                                    peer_station.set(account_id.station_id.to_string());
                                } else {
                                    peer_principal.set(serde_json::to_string(&peer).unwrap_or_default());
                                    peer_station.set(String::new());
                                }
                                edit.set(None); preview.set(None);
                            }
                        },
                        {tr("consent.edit_select")}
                    }
                }
            }
            div { class: "event", "data-testid": "consent-edit-form",
                Label { html_for: "consent-peer-input", {tr("consent.grantee")} }
                Input { id: "consent-peer-input", "data-testid": "consent-peer-input", value: "{peer_principal}", disabled: busy(),
                    oninput: move |event: FormEvent| { peer_principal.set(event.value()); edit.set(None); preview.set(None); }
                }
                Label { html_for: "consent-peer-station-input", {tr("consent.grantee_station_label")} }
                Input { id: "consent-peer-station-input", "data-testid": "consent-peer-station-input", value: "{peer_station}", disabled: busy(),
                    oninput: move |event: FormEvent| { peer_station.set(event.value()); edit.set(None); preview.set(None); }
                }
                Button { variant: ButtonVariant::Secondary, "data-testid": "consent-read-complete-button",
                    disabled: busy() || peer_principal().trim().is_empty(),
                    onclick: move |_| {
                        let Some(account) = active_account() else { return; };
                        let peer = parse_peer(&peer_principal(), &peer_station());
                        let peer = match peer { Ok(peer) => peer, Err(error) => { status.set(error.to_string()); return; } };
                        let captured = generation();
                        let api_token = token();
                        let store = crate::app::runtime_adapter::state_store_handle(session.state_store);
                        let base = account.server_url.to_string();
                        let authority = account.authority.clone();
                        let registered_pcr = account.principal_control_realm_id.clone();
                        edit.set(None); preview.set(None); busy.set(true);
                        spawn(async move {
                            let result = with_authed_sdk_client(&base, api_token, |http| async move {
                                crate::transport::account::read_consent_edit(&http, &store, &authority, &registered_pcr, &peer).await
                            }).await;
                            if captured != generation() { return; }
                            busy.set(false);
                            match result {
                                Ok(value) => match value.permissions().and_then(|p| Ok(serde_json::to_string_pretty(&p)?)) {
                                    Ok(json) => { original.set(json.clone()); draft.set(json); edit.set(Some(value)); status.set(String::new()); }
                                    Err(error) => status.set(error.to_string()),
                                },
                                Err(error) => status.set(error.display()),
                            }
                        });
                    },
                    {tr("consent.read_complete")}
                }
                Button { variant: ButtonVariant::Secondary, "data-testid": "consent-recover-original-button",
                    disabled: busy() || peer_principal().trim().is_empty(),
                    onclick: move |_| {
                        let Some(account) = active_account() else { return; };
                        let peer = match parse_peer(&peer_principal(), &peer_station()) {
                            Ok(peer) => peer, Err(error) => { status.set(error.to_string()); return; }
                        };
                        let captured = generation(); let api_token = token();
                        edit.set(None); preview.set(None); busy.set(true);
                        spawn(async move {
                            let result = with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                                let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
                                let submitter = crate::app::runtime_adapter::event_submitter(http);
                                let result = submitter.recover_pending_consent(&peer).await;
                                fence.check()?;
                                result
                            }).await;
                            if captured != generation() { return; }
                            busy.set(false);
                            match result {
                                Ok(_) => { reload.set(reload() + 1); status.set(tr("consent.recovery_complete")); }
                                Err(error) => status.set(error.display()),
                            }
                        });
                    },
                    {tr("consent.recover_original")}
                }
                if edit().is_some() {
                    p { class: "muted", "data-testid": "consent-expected-current", "{expected_text}" }
                    p { class: "muted", {tr("consent.edit_preserve")} }
                    for scope in [arkret_sdk::ConsentScope::Invite, arkret_sdk::ConsentScope::VoiceCall, arkret_sdk::ConsentScope::VideoCall, arkret_sdk::ConsentScope::Presence] {
                        label {
                            input { r#type: "checkbox", "data-testid": "consent-toggle-{scope.as_str()}",
                                checked: selected_permissions.iter().any(|p| p.consent_scope == scope), disabled: busy(),
                                onchange: move |event: FormEvent| {
                                    match toggle_scope(&draft(), scope, event.checked()) {
                                        Ok(json) => { draft.set(json); preview.set(None); }
                                        Err(error) => status.set(error.to_string()),
                                    }
                                }
                            }
                            {scope_label(scope.as_str())}
                        }
                    }
                    Label { html_for: "consent-permissions-input", {tr("consent.complete_permissions")} }
                    Textarea { id: "consent-permissions-input", rows: "14", value: "{draft}", disabled: busy(), "data-testid": "consent-permissions-input",
                        oninput: move |event: FormEvent| { draft.set(event.value()); preview.set(None); }
                    }
                    Button { variant: ButtonVariant::Secondary, disabled: busy(), "data-testid": "consent-preview-button",
                        onclick: move |_| {
                            if let Some(value) = edit() {
                                match value.replacement(&draft()) {
                                    Ok(payload) => { preview.set(Some(payload)); status.set(String::new()); }
                                    Err(error) => { preview.set(None); status.set(error.to_string()); }
                                }
                            }
                        },
                        {tr("consent.preview")}
                    }
                }
                if preview().is_some() {
                    div { "data-testid": "consent-replacement-diff",
                        strong { {tr("consent.before")} } pre { "{original}" }
                        strong { {tr("consent.after")} } pre { "{preview_text}" }
                    }
                    Button { variant: ButtonVariant::Primary, disabled: busy(), "data-testid": "consent-confirm-replace-button",
                        onclick: move |_| {
                            let (Some(account), Some(value), Some(payload)) = (active_account(), edit(), preview()) else { return; };
                            let captured = generation();
                            let api_token = token();
                            busy.set(true);
                            // Consuming the confirmation prevents a second authored Event after unknown delivery.
                            edit.set(None); preview.set(None);
                            spawn(async move {
                                let result = with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                                    let submitter = crate::app::runtime_adapter::event_submitter(http);
                                    crate::transport::account::replace_consent(&submitter, &value, payload).await
                                }).await;
                                if captured != generation() { return; }
                                busy.set(false);
                                match result {
                                    Ok(_) => { reload.set(reload() + 1); status.set(tr("consent.replace_success")); }
                                    Err(error) => status.set(error.display()),
                                }
                            });
                        },
                        {tr("consent.confirm_replace")}
                    }
                }
            }
            div { class: "event", "data-testid": "consent-request-form",
                strong { {tr("consent.request")} }
                Input { "data-testid": "consent-request-holder-input", value: "{request_holder}", disabled: busy(),
                    placeholder: tr("consent.holder"), oninput: move |event: FormEvent| request_holder.set(event.value()) }
                Input { "data-testid": "consent-request-holder-station-input", value: "{request_station}", disabled: busy(),
                    placeholder: tr("consent.request.holder_station_label"), oninput: move |event: FormEvent| request_station.set(event.value()) }
                Select::<String> { value: Some(request_scope_selected.into()),
                    "data-testid": "consent-request-scope-input",
                    on_value_change: move |value: Option<String>| { if let Some(value) = value { request_scope.set(value); } },
                    for (index, scope) in ["voice_call", "video_call", "presence"].iter().enumerate() {
                        SelectOption::<String> { index, value: scope.to_string(), text_value: scope_label(scope), {scope_label(scope)} }
                    }
                }
                Button { variant: ButtonVariant::Secondary, disabled: busy() || request_holder().trim().is_empty(),
                    "data-testid": "consent-request-submit-button",
                    onclick: move |_| {
                        let Some(account) = active_account() else { return; };
                        let holder = match crate::mls_api_helpers::closed_account_id_input(&request_holder(), Some(&request_station())) {
                            Ok(holder) => holder, Err(error) => { status.set(error.to_string()); return; }
                        };
                        let scope = request_scope(); let api_token = token(); let captured = generation();
                        busy.set(true);
                        spawn(async move {
                            let result = with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                                crate::transport::account::request_consent(&http, &holder, &scope).await
                            }).await;
                            if captured != generation() { return; }
                            busy.set(false);
                            match result { Ok(_) => status.set(tr("consent.request_success")), Err(error) => status.set(error.display()) }
                        });
                    }, {tr("consent.request_submit")}
                }
            }
            if !status().is_empty() { div { class: "muted", "data-testid": "write-status", "{status}" } }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn scope_edit_preserves_expired_future_unknown_and_optional_members() {
        let original = json!([
            {"consent_scope":"invite", "expires_at":"2020-01-01T00:00:00.000Z", "reason":"", "constraints":[]},
            {"consent_scope":"voice_call", "not_before":"2099-01-01T00:00:00.000Z", "constraints":[{"unknown":{"nested":true}}], "evidence_ref":""},
            {"consent_scope":"presence"}
        ]);
        let changed = toggle_scope(
            &original.to_string(),
            arkret_sdk::ConsentScope::VideoCall,
            true,
        )
        .unwrap();
        let changed: serde_json::Value = serde_json::from_str(&changed).unwrap();
        assert_eq!(changed[0], original[0]);
        assert_eq!(changed[1], original[1]);
        assert_eq!(changed[2], json!({"consent_scope":"video_call"}));
        assert_eq!(changed[3], original[2]);
        let removed = toggle_scope(
            &changed.to_string(),
            arkret_sdk::ConsentScope::Invite,
            false,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&removed).unwrap(),
            json!([original[1], changed[2], original[2]])
        );
    }

    #[test]
    fn enabling_present_permission_keeps_its_signed_details() {
        let original = json!([{"consent_scope":"presence", "reason":"original", "constraints":[]}]);
        let result = toggle_scope(
            &original.to_string(),
            arkret_sdk::ConsentScope::Presence,
            true,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&result).unwrap(),
            original
        );
        assert!(
            toggle_scope(
                "not a complete array",
                arkret_sdk::ConsentScope::Presence,
                false
            )
            .is_err()
        );
    }
}
