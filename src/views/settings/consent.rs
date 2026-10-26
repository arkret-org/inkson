//! Complete exact-peer Consent editing with an authenticated read and explicit diff.

use std::rc::Rc;

use glory::prelude::*;

use super::widgets::*;
use crate::i18n::tr;
use crate::presentation::{InksonContext, View};
use crate::transport::account::ConsentEdit;
use crate::transport::auth::with_authed_sdk_client;

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
    crate::operation::ak_ops::consent_actor_peer(principal, Some(station))
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

#[derive(Clone, Copy)]
struct Editor {
    rows: Cage<Vec<arkret_sdk::ConsentView>>,
    status: Cage<String>,
    load_error: Cage<Option<String>>,
    loaded: Cage<bool>,
    reload: Cage<u64>,
    busy: Cage<bool>,
    peer_principal: Cage<String>,
    peer_station: Cage<String>,
    edit: Cage<Option<ConsentEdit>>,
    original: Cage<String>,
    draft: Cage<String>,
    preview: Cage<Option<arkret_sdk::ConsentReplacePayload>>,
    request_scope: Cage<String>,
    request_holder: Cage<String>,
    request_station: Cage<String>,
}

impl Editor {
    fn clear_edit(self) {
        self.edit.revise(|value| {
            *value = None;
        });
        self.preview.revise(|value| {
            *value = None;
        });
    }
    fn message(self, message: String) {
        self.status.revise(|value| {
            *value = message;
        });
    }

    fn read_complete(self, scope: &Scope, context: Rc<InksonContext>) {
        if self.busy.get_untracked() {
            return;
        }
        let Some(account) = context.active_account.get() else {
            return;
        };
        let peer = match parse_peer(&self.peer_principal.get(), &self.peer_station.get()) {
            Ok(peer) => peer,
            Err(error) => {
                self.message(error.to_string());
                return;
            }
        };
        let generation = context.session_generation.get();
        let session = Some(account.clone());
        let api_token = context.token.get();
        let store = context.state_store.handle();
        let authority = account.authority.clone();
        let registered_pcr = account.principal_control_realm_id.clone();
        self.clear_edit();
        self.busy.revise(|value| {
            *value = true;
        });
        spawn(scope, async move {
            let result =
                with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                    crate::transport::account::read_consent_edit(
                        &http,
                        &store,
                        &authority,
                        &registered_pcr,
                        &peer,
                    )
                    .await
                })
                .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            self.busy.revise(|value| {
                *value = false;
            });
            match result {
                Ok(edit) => match edit
                    .permissions()
                    .and_then(|permissions| Ok(serde_json::to_string_pretty(&permissions)?))
                {
                    Ok(json) => {
                        self.original.revise(|value| {
                            *value = json.clone();
                        });
                        self.draft.revise(|value| {
                            *value = json;
                        });
                        self.edit.revise(|value| {
                            *value = Some(edit);
                        });
                        self.message(String::new());
                    }
                    Err(error) => self.message(error.to_string()),
                },
                Err(error) => self.message(error.display()),
            }
        });
    }

    fn recover(self, scope: &Scope, context: Rc<InksonContext>) {
        if self.busy.get_untracked() {
            return;
        }
        let Some(account) = context.active_account.get() else {
            return;
        };
        let peer = match parse_peer(&self.peer_principal.get(), &self.peer_station.get()) {
            Ok(peer) => peer,
            Err(error) => {
                self.message(error.to_string());
                return;
            }
        };
        let generation = context.session_generation.get();
        let session = Some(account.clone());
        let api_token = context.token.get();
        self.clear_edit();
        self.busy.revise(|value| {
            *value = true;
        });
        spawn(scope, async move {
            let result = crate::transport::auth::with_event_submitter(
                account.server_url.as_str(),
                api_token,
                |submitter| async move {
                    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
                    let result = submitter.recover_pending_consent(&peer).await;
                    fence.check()?;
                    result
                },
            )
            .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            self.busy.revise(|value| {
                *value = false;
            });
            match result {
                Ok(_) => {
                    self.reload.revise(|value| *value += 1);
                    self.message(context.tr("consent.recovery_complete"));
                }
                Err(error) => self.message(error.display()),
            }
        });
    }

    fn replace(self, scope: &Scope, context: Rc<InksonContext>) {
        if self.busy.get_untracked() {
            return;
        }
        let (Some(account), Some(edit), Some(payload)) = (
            context.active_account.get(),
            self.edit.get(),
            self.preview.get(),
        ) else {
            return;
        };
        let generation = context.session_generation.get();
        let session = Some(account.clone());
        let api_token = context.token.get();
        self.busy.revise(|value| {
            *value = true;
        });
        // Consume the confirmation before delivery; unknown outcomes require recovery.
        self.clear_edit();
        spawn(scope, async move {
            let result = crate::transport::auth::with_event_submitter(
                account.server_url.as_str(),
                api_token,
                |submitter| async move {
                    crate::transport::account::replace_consent(&submitter, &edit, payload).await
                },
            )
            .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            self.busy.revise(|value| {
                *value = false;
            });
            match result {
                Ok(_) => {
                    self.reload.revise(|value| *value += 1);
                    self.message(context.tr("consent.replace_success"));
                }
                Err(error) => self.message(error.display()),
            }
        });
    }

    fn request(self, scope: &Scope, context: Rc<InksonContext>) {
        if self.busy.get_untracked() {
            return;
        }
        let Some(account) = context.active_account.get() else {
            return;
        };
        let holder = match crate::mls_api_helpers::closed_account_id_input(
            &self.request_holder.get(),
            Some(&self.request_station.get()),
        ) {
            Ok(holder) => holder,
            Err(error) => {
                self.message(error.to_string());
                return;
            }
        };
        let requested_scope = self.request_scope.get();
        let generation = context.session_generation.get();
        let session = Some(account.clone());
        let api_token = context.token.get();
        self.busy.revise(|value| {
            *value = true;
        });
        spawn(scope, async move {
            let result =
                with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                    crate::transport::account::request_consent(&http, &holder, &requested_scope)
                        .await
                })
                .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            self.busy.revise(|value| {
                *value = false;
            });
            match result {
                Ok(_) => self.message(context.tr("consent.request_success")),
                Err(error) => self.message(error.display()),
            }
        });
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>) -> View {
    let editor = Editor {
        rows: scope.cage(Vec::new()),
        status: scope.cage(String::new()),
        load_error: scope.cage(None),
        loaded: scope.cage(false),
        reload: scope.cage(0),
        busy: scope.cage(false),
        peer_principal: scope.cage(String::new()),
        peer_station: scope.cage(String::new()),
        edit: scope.cage(None),
        original: scope.cage(String::new()),
        draft: scope.cage("[]".into()),
        preview: scope.cage(None),
        request_scope: scope.cage("voice_call".into()),
        request_holder: scope.cage(String::new()),
        request_station: scope.cage(String::new()),
    };
    let effect_context = context.clone();
    let weak = scope.downgrade();
    let sequence = std::rc::Rc::new(std::cell::Cell::new(0_u64));
    scope.effect(move || {
        let _ = editor.reload.get();
        let account = effect_context.active_account.get();
        let generation = effect_context.session_generation.get();
        let api_token = effect_context.token.get();
        let serial = sequence.get().wrapping_add(1);
        sequence.set(serial);
        editor.rows.revise(|value| value.clear());
        editor.load_error.revise(|value| {
            *value = None;
        });
        editor.loaded.revise(|value| {
            *value = false;
        });
        editor.busy.revise(|value| {
            *value = false;
        });
        editor.clear_edit();
        editor.message(String::new());
        let Some(account) = account else { return };
        let Some(scope) = weak.upgrade() else { return };
        let context = effect_context.clone();
        let sequence = sequence.clone();
        let session = Some(account.clone());
        spawn(&scope, async move {
            let result =
                with_authed_sdk_client(account.server_url.as_str(), api_token, |http| async move {
                    let list = crate::transport::account::consent_cells(&http).await?;
                    list.validate()?;
                    Ok(list)
                })
                .await;
            if sequence.get() != serial || !context.session_matches(generation, &session) {
                return;
            }
            match result {
                Ok(list) => {
                    editor.rows.revise(|value| {
                        *value = list.consents;
                    });
                    editor.loaded.revise(|value| {
                        *value = true;
                    });
                }
                Err(error) => editor.load_error.revise(|value| {
                    *value = Some(error.display());
                }),
            }
        });
    });
    let enabled = scope.bond(move || !editor.busy.get());
    let list_context = context.clone();
    let row_source = scope.bond(move || (editor.rows.get(), editor.loaded.get()));
    let rows = reactive(row_source, move |scope, (rows, loaded)| {
        let context = list_context.clone();
        let mut children = Vec::new();
        if loaded && rows.is_empty() {
            children.push(paragraph(
                "muted consent-peer-empty",
                context.translated(scope, "consent.empty"),
            ));
        }
        for row in rows {
            let peer = row.peer.clone();
            let mut labels = Vec::new();
            if row.permission_scopes.is_empty() {
                labels.push(plain(context.translated(scope, "consent.closed")));
            }
            labels.extend(
                row.permission_scopes
                    .iter()
                    .map(|value| plain(scope_label(value.as_str()))),
            );
            children.push(stack(
                "event consent-peer-row",
                vec![
                    heading(4, "", consent_peer_label(&row.peer)),
                    line("muted", labels),
                    action(
                        scope,
                        context.clone(),
                        "consent-edit-select",
                        "consent.edit_select",
                        "secondary",
                        enabled,
                        move || {
                            if let arkret_sdk::ConsentPeer::Actor {
                                actor_id: arkret_sdk::ActorId::Account { account_id },
                            } = &peer
                            {
                                editor.peer_principal.revise(|value| {
                                    *value = account_id.principal_id.to_string();
                                });
                                editor.peer_station.revise(|value| {
                                    *value = account_id.station_id.to_string();
                                });
                            } else {
                                editor.peer_principal.revise(|value| {
                                    *value = serde_json::to_string(&peer).unwrap_or_default()
                                });
                                editor.peer_station.revise(|value| value.clear());
                            }
                            editor.clear_edit();
                        },
                    ),
                ],
            ));
        }
        stack("consent-peer-list", children)
    });
    let edit_context = context.clone();
    let edit_fields = reactive(editor.edit, move |scope, edit| {
        let Some(edit) = edit else { return empty() };
        let context = edit_context.clone();
        let expected = edit
            .expected_current()
            .ok()
            .map(|expected| {
                context.tr(match expected {
                    arkret_sdk::ConsentExpectedCurrent::NeverWritten => "consent.never_written",
                    arkret_sdk::ConsentExpectedCurrent::Present { .. } => "consent.existing",
                })
            })
            .unwrap_or_default();
        let mut children = vec![
            paragraph("muted consent-expected-current", expected),
            paragraph("muted", context.translated(scope, "consent.edit_preserve")),
        ];
        for consent_scope in [
            arkret_sdk::ConsentScope::Invite,
            arkret_sdk::ConsentScope::VoiceCall,
            arkret_sdk::ConsentScope::VideoCall,
            arkret_sdk::ConsentScope::Presence,
        ] {
            let checked = scope.bond(move || {
                serde_json::from_str::<Vec<arkret_sdk::ConsentPermission>>(&editor.draft.get())
                    .unwrap_or_default()
                    .iter()
                    .any(|value| value.consent_scope == consent_scope)
            });
            children.push(Box::new(
                sapid::checkbox()
                    .unstyled()
                    .class("checkbox")
                    .label(scope_label(consent_scope.as_str()))
                    .checked(checked)
                    .enabled(enabled)
                    .on_checked_change(move |checked| {
                        match toggle_scope(&editor.draft.get(), consent_scope, checked) {
                            Ok(json) => {
                                editor.draft.revise(|value| {
                                    *value = json;
                                });
                                editor.preview.revise(|value| {
                                    *value = None;
                                });
                            }
                            Err(error) => editor.message(error.to_string()),
                        }
                    }),
            ));
        }
        children.push(field(
            scope,
            context.clone(),
            "consent-permissions-input",
            "consent.complete_permissions",
            editor.draft,
            enabled,
            true,
            move |next| {
                editor.draft.revise(|value| {
                    *value = next;
                });
                editor.preview.revise(|value| {
                    *value = None;
                });
            },
        ));
        children.push(action(
            scope,
            context.clone(),
            "consent-preview-button",
            "consent.preview",
            "secondary",
            enabled,
            move || {
                let Some(edit) = editor.edit.get() else {
                    return;
                };
                match edit.replacement(&editor.draft.get()) {
                    Ok(payload) => {
                        editor.preview.revise(|value| {
                            *value = Some(payload);
                        });
                        editor.message(String::new());
                    }
                    Err(error) => {
                        editor.preview.revise(|value| {
                            *value = None;
                        });
                        editor.message(error.to_string());
                    }
                }
            },
        ));
        stack("consent-permissions-editor", children)
    });
    let preview_context = context.clone();
    let preview = reactive(editor.preview, move |scope, preview| {
        let Some(preview) = preview else {
            return empty();
        };
        let context = preview_context.clone();
        let weak = scope.downgrade();
        let submit_context = context.clone();
        stack(
            "consent-replacement-diff",
            vec![
                heading(4, "", context.translated(scope, "consent.before")),
                paragraph("preformatted", editor.original),
                heading(4, "", context.translated(scope, "consent.after")),
                paragraph(
                    "preformatted",
                    serde_json::to_string_pretty(&preview.permissions).unwrap_or_default(),
                ),
                action(
                    scope,
                    context.clone(),
                    "consent-confirm-replace-button",
                    "consent.confirm_replace",
                    "primary",
                    enabled,
                    move || {
                        if let Some(scope) = weak.upgrade() {
                            editor.replace(&scope, submit_context.clone());
                        }
                    },
                ),
            ],
        )
    });
    let weak_read = scope.downgrade();
    let read_context = context.clone();
    let weak_recover = scope.downgrade();
    let recover_context = context.clone();
    let read_enabled =
        scope.bond(move || !editor.busy.get() && !editor.peer_principal.get().trim().is_empty());
    let weak_request = scope.downgrade();
    let request_context = context.clone();
    let request_enabled =
        scope.bond(move || !editor.busy.get() && !editor.request_holder.get().trim().is_empty());
    let error = reactive(editor.load_error, {
        let context = context.clone();
        move |scope, error| {
            error
                .map(|error| {
                    paragraph(
                        "event error-banner consent-load-error",
                        context.translated_args(scope, "consent.load_failed", move || {
                            vec![("error", error.clone())]
                        }),
                    )
                })
                .unwrap_or_else(|| empty())
        }
    });
    stack(
        "timeline consent-settings-panel",
        vec![
            card(
                scope,
                context.clone(),
                "consent.title",
                vec![
                    paragraph("", context.translated(scope, "consent.edit_intro")),
                    action(
                        scope,
                        context.clone(),
                        "consent-retry-button",
                        "common.refresh",
                        "secondary",
                        enabled,
                        move || editor.reload.revise(|value| *value += 1),
                    ),
                ],
            ),
            error,
            rows,
            stack(
                "event consent-edit-form",
                vec![
                    field(
                        scope,
                        context.clone(),
                        "consent-peer-input",
                        "consent.grantee",
                        editor.peer_principal,
                        enabled,
                        false,
                        move |next| {
                            editor.peer_principal.revise(|value| {
                                *value = next;
                            });
                            editor.clear_edit();
                        },
                    ),
                    field(
                        scope,
                        context.clone(),
                        "consent-peer-station-input",
                        "consent.grantee_station_label",
                        editor.peer_station,
                        enabled,
                        false,
                        move |next| {
                            editor.peer_station.revise(|value| {
                                *value = next;
                            });
                            editor.clear_edit();
                        },
                    ),
                    stack(
                        "consent-edit-actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "consent-read-complete-button",
                                "consent.read_complete",
                                "secondary",
                                read_enabled,
                                move || {
                                    if let Some(scope) = weak_read.upgrade() {
                                        editor.read_complete(&scope, read_context.clone());
                                    }
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "consent-recover-original-button",
                                "consent.recover_original",
                                "secondary",
                                read_enabled,
                                move || {
                                    if let Some(scope) = weak_recover.upgrade() {
                                        editor.recover(&scope, recover_context.clone());
                                    }
                                },
                            ),
                        ],
                    ),
                    edit_fields,
                    preview,
                ],
            ),
            stack(
                "event consent-request-form",
                vec![
                    paragraph(
                        "consent-request-title",
                        context.translated(scope, "consent.request"),
                    ),
                    input_prompt(
                        scope,
                        context.translated(scope, "consent.holder").into(),
                        editor.request_holder,
                        Box::new(
                            sapid::text_field()
                                .unstyled()
                                .class("input consent-request-holder-input")
                                .name(context.translated(scope, "consent.holder"))
                                .value(editor.request_holder)
                                .enabled(enabled)
                                .on_value_change(move |next| {
                                    editor.request_holder.revise(|value| *value = next)
                                }),
                        ),
                    ),
                    input_prompt(
                        scope,
                        context
                            .translated(scope, "consent.request.holder_station_label")
                            .into(),
                        editor.request_station,
                        Box::new(
                            sapid::text_field()
                                .unstyled()
                                .class("input consent-request-holder-station-input")
                                .name(
                                    context
                                        .translated(scope, "consent.request.holder_station_label"),
                                )
                                .value(editor.request_station)
                                .enabled(enabled)
                                .on_value_change(move |next| {
                                    editor.request_station.revise(|value| *value = next)
                                }),
                        ),
                    ),
                    choice(
                        scope,
                        context.clone(),
                        "consent-request-scope-input",
                        "consent.request",
                        editor.request_scope,
                        ["voice_call", "video_call", "presence"]
                            .into_iter()
                            .map(|value| (value.to_owned(), scope_label(value)))
                            .collect(),
                        enabled,
                        move |next| {
                            editor.request_scope.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "consent-request-submit-button",
                        "consent.request_submit",
                        "secondary",
                        request_enabled,
                        move || {
                            if let Some(scope) = weak_request.upgrade() {
                                editor.request(&scope, request_context.clone());
                            }
                        },
                    ),
                ],
            ),
            status(editor.status),
        ],
    )
}
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn complete_actor_and_peer_inputs_preserve_identity_and_reject_missing_dimensions() {
        for actor in [
            json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:peer.example","station_id":"ak:did_core:web:peer-station.example"}}),
            json!({"kind":"service","service_id":"ak:did_core:web:service.example"}),
            json!({"kind":"realm","realm_actor_id":{"realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI","principal_id":"ak:did_core:webvh:zBot"}}),
        ] {
            let wrapped = json!({"kind":"actor","actor_id":actor});
            for candidate in [&actor, &wrapped] {
                assert_eq!(
                    serde_json::to_value(parse_peer(&candidate.to_string(), "").unwrap()).unwrap(),
                    wrapped
                );
            }
        }
        for invalid in [
            json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:peer.example"}}),
            json!({"kind":"realm","realm_actor_id":{"principal_id":"ak:did_core:webvh:zBot"}}),
            json!({"kind":"service","service_id":"ak:did_core:web:service.example","extra":true}),
        ] {
            assert!(parse_peer(&invalid.to_string(), "ak:did_core:web:local.example").is_err());
        }
        assert!(parse_peer("ak:did_core:web:peer.example", "").is_err());
    }

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
