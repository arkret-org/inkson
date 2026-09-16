//! Hydration effects for the Realm members panel.
//!
//! Four `use_effect` blocks that fill the panel's Signals from the local sync
//! projection and the server: the invite modal's contact list, the member
//! roster, the caller's own agents, and the four member-action capability
//! probes. They are effects, not renders, and keeping them beside the rsx made
//! the component read as if they were part of it.

use super::*;

/// Mount every hydration effect the members panel needs.
pub(super) fn use_realm_members_effects(
    controller: RealmMembersController,
    base_url: String,
    principal_id: String,
    selected_realm_id: String,
) {
    let RealmMembersController {
        token,
        mut status_msg,
        mut members,
        mut owned_agents,
        mut permissions,
        mut invite_contacts,
        mut invite_contacts_loaded,
        mut invite_contacts_status,
        invite_modal_open,
        mut state_store,
        ..
    } = controller;
    // Lazily hydrate the contacts list the first time the invite modal opens.
    {
        let base = base_url.clone();
        use_effect(move || {
            if !invite_modal_open() || invite_contacts_loaded() {
                return;
            }
            invite_contacts_loaded.set(true);
            let api_token = token();
            let base = base.clone();
            invite_contacts_status.set(crate::i18n::tr("realm_admin.invite_loading_contacts"));
            spawn(async move {
                match crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move { crate::transport::account::contacts(&http).await },
                )
                .await
                {
                    Ok(response) => {
                        let accepted: Vec<crate::models::ContactListRow> = response
                            .contacts
                            .into_iter()
                            .filter(|c| c.state == arkret_sdk::ContactState::Accepted)
                            .collect();
                        state_store
                            .write()
                            .replace_accepted_human_contacts(&accepted);
                        let count = accepted.len();
                        invite_contacts.set(accepted);
                        invite_contacts_status.set(if count == 0 {
                            crate::i18n::tr("realm_admin.invite_no_contacts")
                        } else {
                            String::new()
                        });
                    }
                    Err(err) => invite_contacts_status.set(
                        crate::i18n::tr("realm_admin.invite_contacts_failed")
                            .replace("{error}", &err.display()),
                    ),
                }
            });
        });
    }
    // Keep the rendered roster in step with the local sync projection.
    {
        let selected_realm_for_hydration = selected_realm_id.clone();
        use_effect(move || {
            let next = projected_member_profiles_for_realm(
                &state_store.read(),
                &selected_realm_for_hydration,
            );
            if members() != next {
                members.set(next);
            }
        });
    }
    // The controller's own agents, which the roster projection does not carry.
    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let fallback_controller_principal_id = principal_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() {
                owned_agents.set(Vec::new());
                return;
            }
            let base = base.clone();
            let realm = realm.clone();
            let fallback_controller_principal_id = fallback_controller_principal_id.clone();
            spawn(async move {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move {
                        fetch_owned_agent_rows(&http, &realm, &fallback_controller_principal_id)
                            .await
                    },
                )
                .await;
                if let Ok(rows) = result {
                    owned_agents.set(rows);
                }
            });
        });
    }
    // Probe the four member-action capabilities; every one fails closed.
    {
        let base = base_url.clone();
        let actor = principal_id.clone();
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() || actor.trim().is_empty() || realm.trim().is_empty() {
                permissions.set(RealmMemberCapabilities {
                    loaded: true,
                    ..RealmMemberCapabilities::default()
                });
                return;
            }
            permissions.set(RealmMemberCapabilities::default());
            let base = base.clone();
            let actor = actor.clone();
            let realm = realm.clone();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    Ok::<_, anyhow::Error>(
                        fetch_realm_member_capabilities(&api, &actor, &realm).await,
                    )
                })
                .await
                {
                    Ok(checks) => {
                        let load = aggregate_realm_member_permissions(&checks);
                        if load.all_checks_failed {
                            status_msg.set(
                                "member action permission check failed; write controls hidden"
                                    .to_owned(),
                            );
                        }
                        permissions.set(load.capabilities);
                    }
                    Err(error) => {
                        permissions.set(RealmMemberCapabilities {
                            loaded: true,
                            ..RealmMemberCapabilities::default()
                        });
                        status_msg.set(format!(
                            "member action permission check failed: {}",
                            error.display()
                        ));
                    }
                }
            });
        });
    }
}
