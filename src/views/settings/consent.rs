//! Exact-peer full-set editing. The signed prestate is frozen before user edits.
use std::sync::Arc;

use dioxus::prelude::*;

use crate::i18n::tr;
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;

fn consent_peer_label(peer: &arkret_sdk::ConsentPeer) -> String {
    match peer {
        arkret_sdk::ConsentPeer::Actor { actor_id } => match actor_id {
            arkret_sdk::ActorId::Realm { realm_actor_id } => realm_actor_id.to_string(),
            arkret_sdk::ActorId::Account { account_id } => format!(
                "{} @ {}",
                account_id.principal_id.as_str(),
                account_id.station_id.as_str()
            ),
            arkret_sdk::ActorId::Service { service_id } => crate::i18n::tr_args(
                "consent.peer_service",
                &[("service", service_id.to_string())],
            ),
        },
    }
}

/// Human label for a wire scope.
fn scope_label(scope: &str) -> String {
    tr(match scope {
        "invite" => "consent.scope.invite",
        "voice_call" => "consent.scope.voice_call",
        "video_call" => "consent.scope.video_call",
        "presence" => "consent.scope.presence",
        _ => "consent.scope.unknown",
    })
}

#[derive(Clone, Debug, PartialEq)]
struct PermissionDraft {
    enabled: bool,
    value: arkret_sdk::ConsentPermission,
    not_before: String,
    expires_at: String,
    constraints: String,
}
impl PermissionDraft {
    fn all(permissions: &[arkret_sdk::ConsentPermission]) -> Vec<Self> {
        arkret_sdk::ConsentScope::ALL
            .iter()
            .map(|scope| {
                let existing = permissions.iter().find(|p| p.consent_scope == *scope);
                let value = existing.cloned().unwrap_or(arkret_sdk::ConsentPermission {
                    consent_scope: *scope,
                    not_before: None,
                    expires_at: None,
                    constraints: None,
                    evidence_ref: None,
                    reason: None,
                });
                Self {
                    enabled: existing.is_some(),
                    not_before: value
                        .not_before
                        .map(arkret_sdk::canonical::format_timestamp_canonical)
                        .unwrap_or_default(),
                    expires_at: value
                        .expires_at
                        .map(arkret_sdk::canonical::format_timestamp_canonical)
                        .unwrap_or_default(),
                    constraints: value
                        .constraints
                        .as_ref()
                        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                        .unwrap_or_default(),
                    value,
                }
            })
            .collect()
    }
    fn finish(&self) -> anyhow::Result<Option<arkret_sdk::ConsentPermission>> {
        if !self.enabled {
            return Ok(None);
        }
        let mut value = self.value.clone();
        let time = |s: &str| -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
            Ok(if s.trim().is_empty() {
                None
            } else {
                Some(s.parse()?)
            })
        };
        value.not_before = time(&self.not_before)?;
        value.expires_at = time(&self.expires_at)?;
        value.constraints = if self.constraints.trim().is_empty() {
            None
        } else {
            Some(serde_json::from_str(&self.constraints)?)
        };
        Ok(Some(value))
    }
}
fn finish_permissions(
    drafts: &[PermissionDraft],
) -> anyhow::Result<Vec<arkret_sdk::ConsentPermission>> {
    let permissions = drafts
        .iter()
        .map(PermissionDraft::finish)
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    arkret_models_collaboration::events_payloads::consent::validate_permissions(&permissions)?;
    Ok(permissions)
}
async fn editor(
    base: String,
    token: String,
    peer: arkret_sdk::ConsentPeer,
) -> anyhow::Result<Arc<crate::transport::account::ConsentEditingSession>> {
    with_authed_sdk_client(&base, token, |http| async move {
        Ok(Arc::new(
            crate::transport::account::read_consent_editing_session(&http, peer).await?,
        ))
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

#[component]
pub fn ConsentSettingsPanel(principal_id: Signal<String>, token: Signal<String>) -> Element {
    let active = crate::app::SessionContext::get().active_account;
    let base_url = move || {
        active()
            .map(|a| a.server_url.to_string())
            .unwrap_or_default()
    };
    let mut reload = use_signal(|| 0_u64);
    let mut editing = use_signal(|| None::<Arc<crate::transport::account::ConsentEditingSession>>);
    let mut drafts = use_signal(Vec::<PermissionDraft>::new);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut peer_principal = use_signal(String::new);
    let mut peer_station = use_signal(String::new);
    let mut request_scope = use_signal(|| "voice_call".to_owned());
    use_effect(move || {
        let _ = active();
        let _ = principal_id();
        editing.set(None);
        drafts.set(Vec::new());
        status.set(String::new());
    });
    let list = use_resource(move || {
        let base = base_url();
        let credential = token();
        let _ = reload();
        async move {
            with_authed_sdk_client(&base, credential, |http| async move {
                crate::transport::account::consent_cells(&http).await
            })
            .await
        }
    });
    let rows = list
        .read()
        .as_ref()
        .and_then(|v| v.as_ref().ok())
        .map(|v| v.consents.clone())
        .unwrap_or_default();
    let editor_rows = drafts();
    rsx! {
        section { "data-testid":"consent-settings-panel",
            h2 { {tr("consent.title")} }
            p { {tr("consent.full_set_help")} }
            label { r#for:"consent-peer",{tr("consent.grantee")} }
            Input { id:"consent-peer","data-testid":"consent-peer-input",value:peer_principal(),oninput:move|e:FormEvent|peer_principal.set(e.value()) }
            label { r#for:"consent-peer-station",{tr("consent.peer_station")} }
            Input { id:"consent-peer-station","data-testid":"consent-peer-station-input",value:peer_station(),oninput:move|e:FormEvent|peer_station.set(e.value()) }
            Button { disabled:busy(),"data-testid":"consent-load-peer-button",onclick:move|_| {
                let peer=crate::operation::ak_ops::consent_actor_peer(&peer_principal(),Some(&peer_station()));
                let base=base_url();let credential=token();busy.set(true);
                spawn(async move {
                    let result=match peer {Ok(peer)=>editor(base,credential,peer).await,Err(e)=>Err(e)};
                    match result.and_then(|session|Ok((PermissionDraft::all(&session.permissions()?),session))) {
                        Ok((values,session))=>{drafts.set(values);editing.set(Some(session));status.set(String::new());},
                        Err(e)=>status.set(e.to_string()),
                    }
                    busy.set(false);
                });
            },{tr("consent.read_full")} }
            div { class:"actions",
                select { "data-testid":"consent-request-scope-input",value:request_scope(),onchange:move|e|request_scope.set(e.value()),
                    for scope in ["voice_call","video_call","presence"] { option {value:scope,{scope_label(scope)}} }
                }
                Button { variant:ButtonVariant::Secondary,disabled:busy(),"data-testid":"consent-request-submit-button",onclick:move|_| {
                    let holder=crate::mls_api_helpers::closed_account_id_input(&peer_principal(),Some(&peer_station()));
                    let base=base_url();let credential=token();let scope=request_scope();busy.set(true);
                    spawn(async move {
                        let result=match holder {Ok(holder)=>with_authed_sdk_client(&base,credential,|http|async move {crate::transport::account::request_consent(&http,&holder,&scope).await}).await.map_err(|error|anyhow::anyhow!(error.display())),Err(e)=>Err(e)};
                        status.set(match result {Ok(_)=>tr("consent.request_success"),Err(e)=>e.to_string()});busy.set(false);
                    });
                },{tr("consent.request_submit")} }
            }
            if let Some(result)=list.read().as_ref() {
                if let Err(error)=result {p {role:"alert",{error.display()}}}
            }
            ul { for row in rows {
                li { "data-testid":"consent-peer-row",
                    span { {consent_peer_label(&row.peer)} }
                    span { {row.permission_scopes.iter().map(|s|scope_label(s.as_str())).collect::<Vec<_>>().join(", ")} }
                    Button { variant:ButtonVariant::Secondary,disabled:busy(),"data-testid":"consent-edit-peer-button",onclick:move|_| {
                        let peer=row.peer.clone();let base=base_url();let credential=token();busy.set(true);
                        spawn(async move {
                            match editor(base,credential,peer).await.and_then(|session|Ok((PermissionDraft::all(&session.permissions()?),session))) {
                                Ok((values,session))=>{drafts.set(values);editing.set(Some(session));status.set(String::new());},
                                Err(e)=>status.set(e.to_string()),
                            }
                            busy.set(false);
                        });
                    },{tr("consent.read_full")} }
                }
            }}
            if let Some(session)=editing() {
                div { "data-testid":"consent-full-editor",
                    h3 { {session.peer().map(consent_peer_label).unwrap_or_default()} }
                    p { {tr("consent.empty_help")} }
                    for (index,draft) in editor_rows.iter().enumerate() {
                        fieldset { disabled:busy(),"data-scope":draft.value.consent_scope.as_str(),
                            legend { {scope_label(draft.value.consent_scope.as_str())} }
                            input { r#type:"checkbox",checked:draft.enabled,"aria-label":scope_label(draft.value.consent_scope.as_str()),onchange:move|e|drafts.write()[index].enabled=e.checked() }
                            if draft.enabled {
                                label { r#for:format!("consent-not_before-{index}"),{tr("consent.not_before")} }
                                Input {id:format!("consent-not_before-{index}"),value:draft.not_before.clone(),oninput:move|e:FormEvent|drafts.write()[index].not_before=e.value()}
                                label { r#for:format!("consent-expires_at-{index}"),{tr("consent.expires_at")} }
                                Input {id:format!("consent-expires_at-{index}"),value:draft.expires_at.clone(),oninput:move|e:FormEvent|drafts.write()[index].expires_at=e.value()}
                                label { r#for:format!("consent-constraints-{index}"),{tr("consent.constraints")} }
                                textarea {id:format!("consent-constraints-{index}"),value:draft.constraints.clone(),oninput:move|e|drafts.write()[index].constraints=e.value()}
                                label { r#for:format!("consent-evidence_ref-{index}"),{tr("consent.evidence_ref")} }
                                Input {id:format!("consent-evidence_ref-{index}"),value:draft.value.evidence_ref.clone().unwrap_or_default(),oninput:move|e:FormEvent|{let s=e.value();drafts.write()[index].value.evidence_ref=(!s.is_empty()).then_some(s);}}
                                label { r#for:format!("consent-reason-{index}"),{tr("consent.reason")} }
                                Input {id:format!("consent-reason-{index}"),value:draft.value.reason.clone().unwrap_or_default(),oninput:move|e:FormEvent|{let s=e.value();drafts.write()[index].value.reason=(!s.is_empty()).then_some(s);}}
                            }
                        }
                    }
                    Button { disabled:busy(),"data-testid":"consent-replace-submit-button",onclick:move|_| {
                        let target=finish_permissions(&drafts());let session=session.clone();let base=base_url();let credential=token();busy.set(true);
                        spawn(async move {
                            let result=match target {Ok(target)=>with_authed_sdk_client(&base,credential,|http|async move {crate::transport::account::replace_consent(&crate::app::runtime_adapter::event_submitter(http),&session,target).await}).await.map_err(|error|anyhow::anyhow!(error.display())),Err(e)=>Err(e)};
                            match result {
                                Ok(result)=>{status.set(if result.status==garth::SendQueueStatus::Committed {tr("consent.replace_success")}else{tr("consent.replace_queued")});editing.set(None);reload.with_mut(|v|*v+=1);},
                                Err(e)=>{status.set(format!("{}: {e}",tr("consent.replace_failed")));editing.set(None);},
                            }
                            busy.set(false);
                        });
                    },{tr("consent.replace_submit")} }
                }
            }
            p {"data-testid":"write-status",role:"status","{status}"}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_editor_preserves_inactive_fields_and_optional_presence() {
        let value = serde_json::json!({"consent_scope":"voice_call","not_before":"2026-01-01T00:00:00.000Z","expires_at":"2026-02-01T00:00:00.000Z","constraints":[{"unknown_rule":true}],"evidence_ref":"","reason":""});
        let permission: arkret_sdk::ConsentPermission =
            serde_json::from_value(value.clone()).unwrap();
        let drafts = PermissionDraft::all(&[permission]);
        let unchanged = finish_permissions(&drafts).unwrap();
        assert_eq!(serde_json::to_value(&unchanged[0]).unwrap(), value);
        let mut removed = drafts;
        removed[1].enabled = false;
        assert!(finish_permissions(&removed).unwrap().is_empty());
    }

    #[test]
    fn consent_scope_and_exact_service_peer_retranslate_without_changing_identity() {
        let peer = arkret_sdk::ConsentPeer::Actor {
            actor_id: arkret_sdk::ActorId::service(
                arkret_sdk::DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            ),
        };
        let original = serde_json::to_string(&peer).unwrap();
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, scope, prefix) in [
                (crate::i18n::UiLocale::En, "Group invites", "service "),
                (crate::i18n::UiLocale::Zh, "群组邀请", "服务 "),
                (crate::i18n::UiLocale::En, "Group invites", "service "),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                assert_eq!(
                    scope_label(arkret_wire::ConsentScope::Invite.as_str()),
                    scope
                );
                assert_eq!(
                    consent_peer_label(&peer),
                    format!("{prefix}ak:did_core:web:service.example")
                );
                assert_eq!(serde_json::to_string(&peer).unwrap(), original);
            }
        });
    }
}
