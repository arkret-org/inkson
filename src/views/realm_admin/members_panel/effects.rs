//! Owner-scoped member hydration from the shared store and authenticated projections.
use super::*;
pub(super) fn mount(
    scope: &Scope,
    context: Rc<InksonContext>,
    controller: RealmMembersController,
    realm: String,
) {
    let members = controller.members;
    let projection_context = context.clone();
    let projection_realm = realm.clone();
    scope.effect(move || {
        let _ = projection_context.state_revision.get();
        let _ = projection_context.sync_cursor.get();
        let next = projection_context
            .state_store
            .read(|store| projected_member_profiles_for_realm(store, &projection_realm));
        if members.get_untracked() != next {
            members.revise(|value| {
                *value = next;
            });
        }
    });
    let load_context = context.clone();
    let load_realm = realm.clone();
    let agents = crate::presentation::widgets::resource(scope, move || {
        let base = load_context.base_url.get();
        let token = load_context.token.get();
        let realm = load_realm.clone();
        let actor = load_context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let _ = load_context.session_generation.get();
        let _ = load_context.owned_agents_rev.get();
        async move {
            if token.trim().is_empty() {
                return Ok(Vec::new());
            }
            crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                fetch_owned_agent_rows(&http, &realm, &actor).await
            })
            .await
            .map_err(|error| error.display())
        }
    });
    let owned_agents = controller.owned_agents;
    scope.effect(move || {
        if let Some(Ok(rows)) = agents.data.get() {
            owned_agents.revise(|value| {
                *value = rows;
            });
        }
    });
    let check_context = context.clone();
    let check_realm = realm.clone();
    let checks = crate::presentation::widgets::resource(scope, move || {
        let base = check_context.base_url.get();
        let token = check_context.token.get();
        let realm = check_realm.clone();
        let actor = check_context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let _ = check_context.session_generation.get();
        async move {
            if token.trim().is_empty() || actor.is_empty() {
                return Err("active session is missing".into());
            }
            with_authed_api(&base, token, |api| async move {
                {
                    let checks = fetch_realm_member_capabilities(&api, &actor, &realm).await;
                    let load = aggregate_realm_member_permissions(&checks);
                    Ok((load.capabilities, load.all_checks_failed))
                }
            })
            .await
            .map_err(|error| error.display())
        }
    });
    let permissions = controller.permissions;
    let status = controller.status_msg;
    scope.effect(move || match checks.data.get() {
        Some(Ok((capabilities, all_checks_failed))) => {
            if all_checks_failed {
                status.revise(|value| {
                    *value = "member action permission check failed; write controls hidden".into();
                });
            }
            permissions.revise(|value| {
                *value = capabilities;
            });
        }
        Some(Err(error)) => {
            permissions.revise(|value| {
                *value = RealmMemberCapabilities {
                    loaded: true,
                    ..Default::default()
                };
            });
            status.revise(|value| {
                *value = format!("member action permission check failed: {error}");
            });
        }
        None => permissions.revise(|value| {
            *value = RealmMemberCapabilities::default();
        }),
    });
    let contacts_context = context.clone();
    let weak = scope.downgrade();
    let open = controller.invite_modal_open;
    let loaded = controller.invite_contacts_loaded;
    let contacts = controller.invite_contacts;
    let feedback = controller.invite_contacts_status;
    scope.effect(move || {
        if !open.get() || loaded.get_untracked() {
            return;
        }
        let Some(scope) = weak.upgrade() else { return };
        let context = contacts_context.clone();
        let generation = context.session_generation.get();
        let session = context.active_account.get();
        let base = context.base_url.get();
        let token = context.token.get();
        loaded.revise(|value| {
            *value = true;
        });
        feedback.revise(|value| {
            *value = context.tr("realm_admin.invite_loading_contacts");
        });
        spawn(&scope, async move {
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                    crate::transport::account::contacts(&http).await
                })
                .await;
            if !context.session_matches(generation, &session) {
                return;
            }
            match result {
                Ok(response) => {
                    let accepted: Vec<_> = response
                        .contacts
                        .into_iter()
                        .filter(|contact| contact.state == arkret_sdk::ContactState::Accepted)
                        .collect();
                    context
                        .state_store
                        .write(|store| store.replace_accepted_human_contacts(&accepted));
                    let empty = accepted.is_empty();
                    contacts.revise(|value| {
                        *value = accepted;
                    });
                    feedback.revise(|value| {
                        *value = if empty {
                            context.tr("realm_admin.invite_no_contacts")
                        } else {
                            String::new()
                        };
                    });
                }
                Err(error) => {
                    loaded.revise(|value| {
                        *value = false;
                    });
                    feedback.revise(|value| {
                        *value = context
                            .tr("realm_admin.invite_contacts_failed")
                            .replace("{error}", &error.display());
                    });
                }
            }
        });
    });
}
