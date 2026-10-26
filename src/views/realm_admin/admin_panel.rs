use std::rc::Rc;

use arkret_wire::{CapabilityActionId, event_kind_str};
use glory::{Cage, Scope};
use serde_json::{Value, json};

use super::metadata::{
    MetadataSubject, metadata_subject_for, projected_members_for_realm, reconcile_editor_value,
    resolve_realm_member_account,
};
use super::policy::build_principal_admission_join_policy;
use super::section::{REALM_ADMIN_NAV_GROUPS, RealmAdminSection};
use crate::models::RealmTreeNodeKind;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

mod agent_policy;
mod controller;
mod management_review;
mod model;

use controller::*;
use model::*;

#[derive(Clone)]
struct AdminPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    realm: String,
    metadata_title: Cage<String>,
    metadata_summary: Cage<String>,
    metadata_avatar_blob_ref: Cage<String>,
    metadata_alias: Cage<String>,
    metadata_loaded_for: Cage<String>,
    metadata_loaded_subject: Cage<Option<MetadataSubject>>,
    join_rule: Cage<String>,
    principal_admission_enabled: Cage<bool>,
    principal_admission_methods: Cage<String>,
    principal_admission_allowed_ids: Cage<String>,
    principal_admission_denied_ids: Cage<String>,
    tighten_history_access: Cage<bool>,
    status_msg: Cage<String>,
    cap_grant_id: Cage<String>,
    cap_tag: Cage<String>,
    cap_subject: Cage<String>,
    cap_revoke_reason: Cage<String>,
    capability_grant_pending: Cage<bool>,
    archive_confirm_open: Cage<bool>,
    destroy_confirm_open: Cage<bool>,
    danger_confirm_text: Cage<String>,
    destroy_reason: Cage<String>,
    leave_confirm_open: Cage<bool>,
    security_diagnostics_open: Cage<bool>,
    advanced_access_open: Cage<bool>,
    admin_subject_id: Cage<String>,
    admin_grant_id: Cage<String>,
    cap_constraint_kind: Cage<String>,
    cap_temporal_not_before: Cage<String>,
    cap_temporal_expires_at: Cage<String>,
    move_detail_open: Cage<Option<String>>,
}
impl AdminPage {
    fn new(scope: &Scope, context: Rc<InksonContext>, realm: String) -> Self {
        Self {
            metadata_title: scope.cage((String::new)()),
            metadata_summary: scope.cage((String::new)()),
            metadata_avatar_blob_ref: scope.cage((String::new)()),
            metadata_alias: scope.cage((String::new)()),
            metadata_loaded_for: scope.cage((String::new)()),
            metadata_loaded_subject: scope.cage(Option::<MetadataSubject>::None),
            join_rule: scope.cage("public".to_owned()),
            principal_admission_enabled: scope.cage(false),
            principal_admission_methods: scope.cage("did:webvh".to_owned()),
            principal_admission_allowed_ids: scope.cage((String::new)()),
            principal_admission_denied_ids: scope.cage((String::new)()),
            tighten_history_access: scope.cage(false),
            status_msg: scope.cage((String::new)()),
            cap_grant_id: scope.cage((String::new)()),
            cap_tag: scope.cage(CapabilityActionId::MESSAGE_CREATE.to_owned()),
            cap_subject: scope.cage((String::new)()),
            cap_revoke_reason: scope.cage("rotation policy".to_owned()),
            capability_grant_pending: scope.cage(false),
            archive_confirm_open: scope.cage(false),
            destroy_confirm_open: scope.cage(false),
            danger_confirm_text: scope.cage((String::new)()),
            destroy_reason: scope.cage("operator_request".to_owned()),
            leave_confirm_open: scope.cage(false),
            security_diagnostics_open: scope.cage(false),
            advanced_access_open: scope.cage(false),
            admin_subject_id: scope.cage((String::new)()),
            admin_grant_id: scope.cage((String::new)()),
            cap_constraint_kind: scope.cage("none".to_owned()),
            cap_temporal_not_before: scope.cage((String::new)()),
            cap_temporal_expires_at: scope.cage((String::new)()),
            move_detail_open: scope.cage(Option::<String>::None),
            owner: scope.downgrade(),
            context,
            realm,
        }
    }
    fn command(&self) -> RealmAdminController {
        RealmAdminController {
            owner: self.owner.clone(),
            status_msg: self.status_msg,
            sync_cursor: self.context.sync_cursor,
            state_store: self.context.state_store.clone(),
            metadata_alias: self.metadata_alias,
            admin_grant_id: self.admin_grant_id,
            capability_grant_pending: self.capability_grant_pending,
            capability_grant_id: self.cap_grant_id,
        }
    }
    #[allow(unused_variables)]
    fn save_profile(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let metadata_title = self.metadata_title;
        let metadata_summary = self.metadata_summary;
        let metadata_avatar_blob_ref = self.metadata_avatar_blob_ref;
        let metadata_alias = self.metadata_alias;
        let status_msg = self.status_msg;
        let action = {
            let base = base_url.clone();
            let subject_id = selected_realm_id.clone();
            let subject_kind = metadata_subject.kind;
            let home_realm_id = metadata_subject.home_realm_id.clone();
            let stored_summary = metadata_subject.summary.trim().to_owned();
            let actor_principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let subject_id = subject_id.clone();
                let home_realm_id = home_realm_id.clone();
                let api_token = token.get();
                let title = metadata_title.get().trim().to_owned();
                let summary = metadata_summary.get().trim().to_owned();
                let avatar_blob_ref = metadata_avatar_blob_ref.get().trim().to_owned();
                let alias = metadata_alias.get().trim().to_owned();
                let updates_alias = subject_kind == RealmTreeNodeKind::Realm && !alias.is_empty();
                if title.is_empty() {
                    status_msg.revise(|value| {
                        *value = "profile update failed: title is required by spec".to_owned();
                    });
                    return;
                }
                // The SDK `BlobRef` newtype is the gate:
                // an `ak:blob:` prefix test admits values
                // `common-ids.schema.json` rejects, and the
                // publish path already re-validates through the
                // same type.
                if !avatar_blob_ref.is_empty()
                    && arkret_sdk::BlobRef::new(avatar_blob_ref.clone()).is_err()
                {
                    status_msg.revise(|value|{*value="profile update failed: avatar_blob_ref must be a canonical blob reference".to_owned();});
                    return;
                }
                // Realm/Space metadata events are authored by the
                // account/principal DID, not the device DID, or the server
                // rejects them with `actor_session_mismatch`.
                let actor_id = actor_principal_id.trim().to_owned();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "profile update failed: account is not connected".to_owned();
                    });
                    return;
                }
                let mut patch = serde_json::Map::new();
                patch.insert("title".to_owned(), json!(title));
                // `summary` is an ordinary optional member, not a
                // redactable content-carrier slot: only `content` /
                // `encrypted_content` are registered in
                // `redactable-field-registry.json`, so
                // `event-and-patch.md` §4.2.4 makes `$op: unset` the
                // non-terminal clear path here, exactly as for
                // `avatar_blob_ref` below. A Realm profile is a full
                // restatement of the singleton `ak.realm.profile` facet,
                // where the same op reads as "no summary".
                if !summary.is_empty() {
                    patch.insert("summary".to_owned(), json!(summary));
                } else if !stored_summary.is_empty() {
                    patch.insert("summary".to_owned(), json!({ "$op": "unset" }));
                }
                patch.insert(
                    "avatar_blob_ref".to_owned(),
                    if avatar_blob_ref.is_empty() {
                        json!({ "$op": "unset" })
                    } else {
                        json!(avatar_blob_ref)
                    },
                );
                let patch = Value::Object(patch);
                let accepted_title = title.clone();
                let accepted_summary = (!summary.is_empty()).then_some(summary.clone());
                let accepted_avatar =
                    (!avatar_blob_ref.is_empty()).then_some(avatar_blob_ref.clone());
                controller.save_metadata(
                    base,
                    api_token,
                    actor_id,
                    MetadataWriteSubject {
                        home_realm_id,
                        subject_id,
                        kind: subject_kind,
                        event_kind: metadata_event_kind,
                        updates_alias,
                    },
                    patch,
                    alias,
                    AcceptedRealmProfile {
                        title: accepted_title,
                        summary: accepted_summary,
                        avatar_blob_ref: accepted_avatar,
                    },
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn remove_alias(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let action = {
            let base = base_url.clone();
            let home_realm_id = metadata_subject.home_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let home_realm_id = home_realm_id.clone();
                let actor_id = actor_principal_id.trim().to_owned();
                let api_token = token.get();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "alias removal failed: account is not connected".to_owned();
                    });
                    return;
                }
                controller.remove_alias(base, api_token, actor_id, home_realm_id);
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn apply_policy(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let join_rule = self.join_rule;
        let principal_admission_enabled = self.principal_admission_enabled;
        let principal_admission_methods = self.principal_admission_methods;
        let principal_admission_allowed_ids = self.principal_admission_allowed_ids;
        let principal_admission_denied_ids = self.principal_admission_denied_ids;
        let tighten_history_access = self.tighten_history_access;
        let status_msg = self.status_msg;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor = principal_id.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let actor = actor.clone();
                let api_token = token.get();
                let rule = join_rule.get();
                let tighten_access = tighten_history_access.get();
                let join_policy = match build_principal_admission_join_policy(
                    principal_admission_enabled.get(),
                    &principal_admission_methods.get(),
                    &principal_admission_allowed_ids.get(),
                    &principal_admission_denied_ids.get(),
                ) {
                    Ok(policy) => policy,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("policy failed: {err}");
                        });
                        return;
                    }
                };
                controller.apply_policy(
                    base,
                    api_token,
                    realm,
                    actor,
                    rule,
                    tighten_access,
                    join_policy,
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn rotate(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            let device = device_id.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let actor_id = actor_principal_id.trim().to_owned();
                let device = device.clone();
                let api_token = token.get();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "rotate failed: account is not connected".to_owned();
                    });
                    return;
                }
                // Build the forced self-update commit + the
                // canonical ak.mls.commit event locally.
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                let Some(account) = context.active_account.get() else {
                    status_msg.revise(|value| {
                        *value = "rotate failed: active account context is unavailable".to_owned();
                    });
                    return;
                };
                if account.principal_id().as_str() != actor_id
                    || account.device_id.as_str() != device
                {
                    status_msg.revise(|value| {
                        *value = "rotate failed: active account authority changed".to_owned();
                    });
                    return;
                }
                controller.rotate_mls_epoch(
                    base,
                    api_token,
                    realm,
                    actor_id,
                    device,
                    account,
                    secure_store,
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn leave(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let leave_confirm_open = self.leave_confirm_open;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                // Membership events are authored by the account/principal DID
                // (the authenticated session actor), not the device DID, or the server
                // rejects them with `actor_session_mismatch`.
                let actor_id = actor_principal_id.trim().to_owned();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "Leave Realm failed: account is not connected".to_owned();
                    });
                    return;
                }
                leave_confirm_open.revise(|value| {
                    *value = false;
                });
                controller.leave_realm(base, api_token, realm, actor_id);
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn grant(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let cap_tag = self.cap_tag;
        let cap_subject = self.cap_subject;
        let capability_grant_pending = self.capability_grant_pending;
        let cap_constraint_kind = self.cap_constraint_kind;
        let cap_temporal_not_before = self.cap_temporal_not_before;
        let cap_temporal_expires_at = self.cap_temporal_expires_at;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            let issuer_authority_basis = issuer_authority_basis.clone();
            move |_| {
                if capability_grant_pending.get() {
                    return;
                }
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let tag_val = cap_tag.get().trim().to_owned();
                let subject_val = cap_subject.get().trim().to_owned();
                if tag_val.is_empty() || subject_val.is_empty() {
                    status_msg.revise(|value| {
                        *value =
                            "fill tag + subject DID before submitting capability grant".to_owned();
                    });
                    return;
                }
                // Capability events are authored by the account/principal DID,
                // not the device DID, or the server returns
                // `actor_session_mismatch`.
                let actor_id = actor_principal_id.trim().to_owned();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "capability grant failed: account is not connected".to_owned();
                    });
                    return;
                }
                let Some(issuer_authority_basis) = issuer_authority_basis.clone() else {
                    status_msg.revise(|value|{*value="capability grant blocked: verified Realm delegation-root basis is unavailable"
                                            .to_owned();});
                    return;
                };
                // The subject is closed against the Realm roster (or pasted
                // as the full selector); a bare principal is never completed
                // with this client's Station.
                let subject_account = match state_store
                    .read(|store| resolve_realm_member_account(store, &realm, &subject_val))
                {
                    Ok(subject) => subject,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("capability grant failed: {err}");
                        });
                        return;
                    }
                };
                // Pull the active constraint from the editor
                // signals into the canonical `grant-constraint`
                // shape (`{constraint_kind, effect, …}`). Empty
                // input yields no constraint. `expires_at` is the
                // grant's own validity bound, so it is threaded
                // through the builder directly (not as a
                // constraint) while the temporal constraint keeps
                // only `not_before`.
                let kind = cap_constraint_kind.get();
                let expires_at_val = cap_temporal_expires_at.get().trim().to_owned();
                let expires_at_opt = if kind == "temporal" && !expires_at_val.is_empty() {
                    Some(expires_at_val.clone())
                } else {
                    None
                };
                let constraint_json: serde_json::Value = if kind == "temporal" {
                    let nb = cap_temporal_not_before.get();
                    let nb_trim = nb.trim();
                    if nb_trim.is_empty() && expires_at_opt.is_none() {
                        serde_json::Value::Null
                    } else {
                        let mut constraint = serde_json::Map::new();
                        constraint.insert(
                            "constraint_kind".into(),
                            serde_json::Value::String("temporal".to_owned()),
                        );
                        constraint.insert(
                            "effect".into(),
                            serde_json::Value::String("allow".to_owned()),
                        );
                        if !nb_trim.is_empty() {
                            constraint.insert(
                                "not_before".into(),
                                serde_json::Value::String(nb_trim.to_owned()),
                            );
                        }
                        if let Some(ea) = expires_at_opt.as_deref() {
                            constraint.insert(
                                "expires_at".into(),
                                serde_json::Value::String(ea.to_owned()),
                            );
                        }
                        json!([serde_json::Value::Object(constraint)])
                    }
                } else {
                    serde_json::Value::Null
                };
                let envelope = crate::operation::ak_ops::capability_grant_actions(
                    &realm,
                    &actor_id,
                    &subject_account,
                    &[tag_val.as_str()],
                    expires_at_opt.as_deref(),
                    constraint_json,
                    &issuer_authority_basis,
                )
                .and_then(|builder| builder.build_sdk_event("inkson"));
                let envelope = match envelope {
                    Ok(envelope) => envelope,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("capability.grant build failed: {err}");
                        });
                        return;
                    }
                };
                controller.submit_capability_grant(base, api_token, envelope);
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn revoke(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let cap_grant_id = self.cap_grant_id;
        let cap_subject = self.cap_subject;
        let cap_revoke_reason = self.cap_revoke_reason;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let grant_val = cap_grant_id.get().trim().to_owned();
                let subject_val = cap_subject.get().trim().to_owned();
                let reason_val = cap_revoke_reason.get();
                let reason_opt = if reason_val.trim().is_empty() {
                    None
                } else {
                    Some(reason_val.clone())
                };
                if grant_val.is_empty() || subject_val.is_empty() {
                    status_msg.revise(|value| {
                        *value = "fill grant_id + subject DID before reading the current Grant row"
                            .to_owned();
                    });
                    return;
                }
                // Capability events are authored by the account/principal DID,
                // not the device DID, or the server returns
                // `actor_session_mismatch`.
                let actor_id = actor_principal_id.trim().to_owned();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "capability revoke failed: account is not connected".to_owned();
                    });
                    return;
                }
                let subject = match state_store
                    .read(|store| resolve_realm_member_account(store, &realm, &subject_val))
                {
                    Ok(subject) => subject,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("capability revoke blocked: {err}");
                        });
                        return;
                    }
                };
                controller.revoke_capability_from_effective_row(
                    base,
                    api_token,
                    realm,
                    actor_id,
                    arkret_sdk::ActorId::account(subject),
                    grant_val,
                    reason_opt,
                    "capability.revoke",
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn grant_admin(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let admin_subject_id = self.admin_subject_id;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            let issuer_authority_basis = issuer_authority_basis.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let subject = admin_subject_id.get().trim().to_owned();
                let actor_id = actor_principal_id.trim().to_owned();
                if subject.is_empty() {
                    status_msg.revise(|value| {
                        *value = crate::i18n::tr("realm_admin.admin_subject_required");
                    });
                    return;
                }
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "set admin failed: account is not connected".to_owned();
                    });
                    return;
                }
                let Some(issuer_authority_basis) = issuer_authority_basis.clone() else {
                    status_msg.revise(|value|{*value="set admin blocked: verified Realm delegation-root basis is unavailable"
                                            .to_owned();});
                    return;
                };
                let subject = match state_store
                    .read(|store| resolve_realm_member_account(store, &realm, &subject))
                {
                    Ok(subject) => subject,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("set admin failed: {err}");
                        });
                        return;
                    }
                };
                controller.grant_realm_admin(
                    base,
                    api_token,
                    realm,
                    actor_id,
                    subject,
                    issuer_authority_basis,
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn revoke_admin(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let admin_subject_id = self.admin_subject_id;
        let admin_grant_id = self.admin_grant_id;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let grant_id = admin_grant_id.get().trim().to_owned();
                let subject = admin_subject_id.get().trim().to_owned();
                let actor_id = actor_principal_id.trim().to_owned();
                if grant_id.is_empty() || subject.is_empty() {
                    status_msg.revise(|value|{*value="revoke admin blocked: subject and grant id are required to read the current Grant row"
                                            .to_owned();});
                    return;
                }
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "revoke admin failed: account is not connected".to_owned();
                    });
                    return;
                }
                let subject = match state_store
                    .read(|store| resolve_realm_member_account(store, &realm, &subject))
                {
                    Ok(subject) => subject,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("revoke admin blocked: {err}");
                        });
                        return;
                    }
                };
                controller.revoke_capability_from_effective_row(
                    base,
                    api_token,
                    realm,
                    actor_id,
                    arkret_sdk::ActorId::account(subject),
                    grant_id,
                    Some("admin_revoke".to_owned()),
                    "revoked ak.realm.admin",
                );
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn danger(&self) {
        let context = self.context.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let sync_cursor = context.sync_cursor;
        let frontier_state = context.frontier_state;
        let selected_realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let device_id = context.device_id.get();
        let state_store = context.state_store.clone();
        let controller = self.command();
        let metadata_subject = context
            .state_store
            .read(|store| metadata_subject_for(store, &self.realm));
        let metadata_event_kind = if metadata_subject.kind == RealmTreeNodeKind::Realm {
            event_kind_str::REALM_PROFILE
        } else {
            event_kind_str::SPACE_UPDATE
        };
        let issuer_authority_basis = context.state_store.read(|store| {
            store.active_authority().and_then(|issuer| {
                capability_issuer_basis(
                    &self.realm,
                    &store.realm_current_state_entries(&self.realm),
                    &issuer,
                )
            })
        });
        let is_destroy = self.destroy_confirm_open.get();
        let status_msg = self.status_msg;
        let archive_confirm_open = self.archive_confirm_open;
        let destroy_confirm_open = self.destroy_confirm_open;
        let danger_confirm_text = self.danger_confirm_text;
        let destroy_reason = self.destroy_reason;
        let action = {
            let base = base_url.clone();
            let realm = selected_realm_id.clone();
            let actor_principal_id = principal_id.clone();
            move |_| {
                if danger_confirm_text.get().trim() != realm.trim() {
                    status_msg.revise(|value| {
                        *value = "confirmation did not match the Realm ID".to_owned();
                    });
                    return;
                }
                let base = base.clone();
                let realm = realm.clone();
                let api_token = token.get();
                let actor_id = actor_principal_id.trim().to_owned();
                if actor_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = format!(
                            "{} failed: account is not connected",
                            if is_destroy { "destroy" } else { "archive" }
                        );
                    });
                    return;
                }
                archive_confirm_open.revise(|value| {
                    *value = false;
                });
                destroy_confirm_open.revise(|value| {
                    *value = false;
                });
                danger_confirm_text.revise(|value| {
                    *value = String::new();
                });
                let reason = destroy_reason.get().trim().to_owned();
                controller
                    .archive_or_destroy_realm(base, api_token, realm, actor_id, reason, is_destroy);
            }
        };
        action(());
    }
}

pub(super) fn page(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
    section: RealmAdminSection,
) -> View {
    let state = AdminPage::new(scope, context.clone(), realm.clone());
    let sync_state = state.clone();
    let sync_context = context.clone();
    scope.effect(move || {
        let _ = sync_context.state_revision.get();
        let _ = sync_context.sync_cursor.get();
        let subject = sync_context
            .state_store
            .read(|store| metadata_subject_for(store, &sync_state.realm));
        let title = sync_state.metadata_title.get_untracked();
        let summary = sync_state.metadata_summary.get_untracked();
        let avatar = sync_state.metadata_avatar_blob_ref.get_untracked();
        let loaded_for = sync_state.metadata_loaded_for.get_untracked();
        let previous = sync_state.metadata_loaded_subject.get_untracked();
        let patch = reconcile_metadata_editors(
            &sync_state.realm,
            &subject,
            MetadataEditorState {
                loaded_for: &loaded_for,
                loaded_subject: previous.as_ref(),
                title: &title,
                summary: &summary,
                avatar_blob_ref: &avatar,
            },
        );
        if let Some(value) = patch.title {
            sync_state.metadata_title.revise(|current| *current = value);
        }
        if let Some(value) = patch.summary {
            sync_state
                .metadata_summary
                .revise(|current| *current = value);
        }
        if let Some(value) = patch.avatar_blob_ref {
            sync_state
                .metadata_avatar_blob_ref
                .revise(|current| *current = value);
        }
        if let Some(value) = patch.loaded_for {
            sync_state
                .metadata_loaded_for
                .revise(|current| *current = value);
        }
        if let Some(value) = patch.loaded_subject {
            sync_state
                .metadata_loaded_subject
                .revise(|current| *current = Some(value));
        }
    });
    let overview_context = context.clone();
    let overview_realm = realm.clone();
    let overview = scope.bond(move || {
        let _ = overview_context.state_revision.get();
        let _ = overview_context.sync_cursor.get();
        overview_context.state_store.read(|store| {
            let count = projected_members_for_realm(store, &overview_realm).len();
            let alerts =
                realm_security_health(store.realm_has_pending_mls_binding(&overview_realm))
                    .alert_count;
            let kind = metadata_subject_for(store, &overview_realm).kind;
            (
                count,
                alerts,
                if kind == RealmTreeNodeKind::Space {
                    "Space"
                } else {
                    "Realm"
                },
            )
        })
    });
    let subject_label = scope.bond(move || overview.get().2.to_owned());
    let mut groups = Vec::new();
    for (index, (label, sections)) in REALM_ADMIN_NAV_GROUPS.iter().copied().enumerate() {
        let mut items = vec![paragraph("settings-nav-group-label", label.to_string())];
        for next in sections.iter().copied() {
            let nav = context.clone();
            let realm = realm.clone();
            items.push(action(
                scope,
                context.clone(),
                &format!("realm-admin-nav-item-{}", next.slug().unwrap_or("overview")),
                next.label(),
                if next == section {
                    "settings-nav-item active"
                } else {
                    "settings-nav-item"
                },
                true,
                move || nav.navigate(next.route(realm.clone())),
            ));
        }
        groups.push(stack("settings-nav-cluster", items));
        if index + 1 < REALM_ADMIN_NAV_GROUPS.len() {
            groups.push(stack("settings-nav-divider", vec![]));
        }
    }
    let content = match section {
        RealmAdminSection::Overview => {
            let link = |key: &str, label: String, route: Route| -> View {
                let nav = context.clone();
                Box::new(
                    crate::presentation::widgets::internal_link()
                        .class(format!("secondary {key}"))
                        .name(label.clone())
                        .target(route.to_string())
                        .fill(plain(label))
                        .on(glory::render::EventKind::Activate, move |_| {
                            nav.navigate(route.clone())
                        }),
                )
            };
            let metric =
                |label: View, value: View, link: View| stack("metric", vec![label, value, link]);
            let label = |value: glory::Lotus<String>| {
                Box::new(
                    glory::prelude::text()
                        .class("realm-overview-label")
                        .content(value),
                ) as View
            };
            stack(
                "event realm-admin-overview",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain("Realm settings"),
                            Box::new(
                                glory::prelude::view()
                                    .class("realm-overview-identity")
                                    .name(realm.clone())
                                    .fill(
                                        glory::prelude::text().content(short_protocol_id(&realm)),
                                    ),
                            ),
                        ],
                    ),
                    stack(
                        "metric-grid",
                        vec![
                            metric(
                                label(context.translated(scope, "realm_admin.members").into()),
                                plain(scope.bond(move || format!("{} known", overview.get().0))),
                                link(
                                    "realm-overview-members",
                                    "Open Members".into(),
                                    Route::RealmMembers {
                                        realm_id: realm.clone(),
                                    },
                                ),
                            ),
                            metric(
                                label("Profile".to_owned().into()),
                                plain(scope.bond(move || {
                                    format!("{} title, summary, avatar", subject_label.get())
                                })),
                                link(
                                    "realm-overview-profile",
                                    "Open Profile".into(),
                                    RealmAdminSection::Profile.route(realm.clone()),
                                ),
                            ),
                            metric(
                                label(context.translated(scope, "realm_admin.access").into()),
                                plain(state.join_rule),
                                link(
                                    "realm-overview-access",
                                    "Open Access".into(),
                                    RealmAdminSection::Access.route(realm.clone()),
                                ),
                            ),
                            metric(
                                label("Security & repair".to_owned().into()),
                                plain(scope.bond(move || format!("{} alerts", overview.get().1))),
                                link(
                                    "realm-overview-security",
                                    "Open Security".into(),
                                    RealmAdminSection::Security.route(realm.clone()),
                                ),
                            ),
                        ],
                    ),
                ],
            )
        }
        RealmAdminSection::Profile => profile_view(scope, &state),
        RealmAdminSection::Access => access_view(scope, &state),
        RealmAdminSection::Security => security_view(scope, &state),
        RealmAdminSection::Federation => stack(
            "settings-content-stack",
            vec![
                card(
                    scope,
                    context.clone(),
                    "Federation trust",
                    vec![paragraph(
                        "muted",
                        "Trust bundle import, validation, and revocation are not wired in inkson. Use the deployment's admin tooling for federation trust changes.",
                    )],
                ),
                super::organization::page(scope, context.clone(), realm.clone()),
            ],
        ),
        RealmAdminSection::Moderation => crate::views::moderation::page(
            scope,
            context.clone(),
            Route::RealmAdminSection {
                realm_id: realm.clone(),
                section: "moderation".into(),
            },
        ),
        RealmAdminSection::Repair => repair_view(scope, &state),
    };
    let members = context.clone();
    let members_realm = realm.clone();
    stack(
        "settings realm-settings",
        vec![stack(
            "settings-shell realm-settings-shell",
            vec![
                stack("settings-sidebar-column", groups),
                stack(
                    "settings-content-column realm-settings-content",
                    vec![
                        stack(
                            "event settings-content-hero",
                            vec![
                                line(
                                    "settings-content-title-row",
                                    vec![
                                        heading(2, "settings-content-title", section.label()),
                                        Box::new(
                                            glory::prelude::text()
                                                .class("badge realm-admin-subject-badge")
                                                .content(subject_label),
                                        ),
                                    ],
                                ),
                                action(
                                    scope,
                                    context.clone(),
                                    "realm-admin-open-members",
                                    "realm_admin.members",
                                    "secondary",
                                    true,
                                    move || {
                                        members.navigate(Route::RealmMembers {
                                            realm_id: members_realm.clone(),
                                        })
                                    },
                                ),
                            ],
                        ),
                        content,
                        status(state.status_msg),
                    ],
                ),
            ],
        )],
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod overview_surface_tests;

fn profile_view(scope: &Scope, state: &AdminPage) -> View {
    let context = state.context.clone();
    let title = state.metadata_title;
    let summary = state.metadata_summary;
    let alias = state.metadata_alias;
    let avatar = state.metadata_avatar_blob_ref;
    let status = state.status_msg;
    let subject = context
        .state_store
        .read(|store| metadata_subject_for(store, &state.realm));
    let save = state.clone();
    let remove = state.clone();
    let avatar_context = context.clone();
    let home_realm = subject.home_realm_id.clone();
    let uploader = reactive(avatar, move |scope, current| {
        crate::components::avatar_uploader(
            scope,
            avatar_context.clone(),
            crate::components::AvatarUploaderProps {
                current_blob_ref: current,
                alt_text: "Realm avatar".into(),
                api_token: avatar_context.token.get(),
                upload_realm_id: Some(home_realm.clone()),
                test_id_prefix: "realm-avatar".into(),
                on_uploaded: Rc::new(move |blob_ref| {
                    avatar.revise(|value| {
                        *value = blob_ref;
                    });
                    status.revise(|value| {
                        *value = "avatar uploaded; Save Profile publishes it".into();
                    });
                }),
                on_clear: Rc::new(move |()| {
                    avatar.revise(|value| value.clear());
                    status.revise(|value| {
                        *value = "avatar cleared; Save Profile publishes it".into();
                    });
                }),
            },
        )
    });
    card(
        scope,
        context.clone(),
        if subject.kind == RealmTreeNodeKind::Realm {
            "Realm Profile"
        } else {
            "Space Profile"
        },
        vec![
            paragraph("muted mono", short_protocol_id(&state.realm)),
            stack(
                "workflow-form",
                vec![
                    input(
                        scope,
                        context.clone(),
                        "realm-name-input",
                        "Title",
                        title,
                        true,
                    ),
                    field(
                        scope,
                        context.clone(),
                        "realm-summary-input",
                        "Summary",
                        summary,
                        true,
                        true,
                        move |next| {
                            summary.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    input(
                        scope,
                        context.clone(),
                        "realm-alias-input",
                        "Alias",
                        alias,
                        subject.kind == RealmTreeNodeKind::Realm,
                    ),
                    uploader,
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "update-metadata-button",
                                "realm_admin.save_profile",
                                "primary",
                                true,
                                move || save.save_profile(),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "remove-realm-alias-button",
                                "Remove Alias",
                                "secondary",
                                subject.kind == RealmTreeNodeKind::Realm,
                                move || remove.remove_alias(),
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )
}
fn access_view(scope: &Scope, state: &AdminPage) -> View {
    let context = state.context.clone();
    let join = state.join_rule;
    let admission = state.principal_admission_enabled;
    let tighten = state.tighten_history_access;
    let apply = state.clone();
    let mut rules = Vec::new();
    for rule in ["public", "invite", "knock", "restricted"] {
        rules.push(action(
            scope,
            context.clone(),
            &format!("join-rule-{rule}"),
            rule,
            "secondary",
            true,
            move || {
                join.revise(|value| {
                    *value = rule.to_owned();
                })
            },
        ));
    }
    let methods = state.principal_admission_methods;
    let allowed = state.principal_admission_allowed_ids;
    let denied = state.principal_admission_denied_ids;
    stack(
        "settings-content-stack",
        vec![
            agent_policy::page(scope, context.clone(), state.realm.clone()),
            management_review::page(scope, context.clone(), state.realm.clone()),
            card(
                scope,
                context.clone(),
                "Join Policy",
                vec![line("actions", rules), plain(join)],
            ),
            card(
                scope,
                context.clone(),
                "Principal Admission",
                vec![
                    toggle(
                        scope,
                        context.clone(),
                        "principal-admission-enabled",
                        "Enabled",
                        admission,
                        true,
                        move |next| {
                            admission.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    input(
                        scope,
                        context.clone(),
                        "principal-admission-methods-input",
                        "Allowed DID methods",
                        methods,
                        admission,
                    ),
                    field(
                        scope,
                        context.clone(),
                        "principal-admission-allowed-ids-input",
                        "Allowed principal ids",
                        allowed,
                        admission,
                        true,
                        move |next| {
                            allowed.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    field(
                        scope,
                        context.clone(),
                        "principal-admission-denied-ids-input",
                        "Denied principal ids",
                        denied,
                        admission,
                        true,
                        move |next| {
                            denied.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                ],
            ),
            card(
                scope,
                context.clone(),
                "History Access",
                vec![
                    toggle(
                        scope,
                        context.clone(),
                        "tighten-history-access",
                        "Tighten to since joining",
                        tighten,
                        true,
                        move |next| {
                            tighten.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "apply-policy-button",
                        "realm_admin.apply_policy",
                        "primary",
                        true,
                        move || apply.apply_policy(),
                    ),
                ],
            ),
        ],
    )
}
fn security_view(scope: &Scope, state: &AdminPage) -> View {
    let context = state.context.clone();
    let pending = context
        .state_store
        .read(|store| store.realm_has_pending_mls_binding(&state.realm));
    let health = realm_security_health(pending);
    let diagnostics = state.security_diagnostics_open;
    let advanced = state.advanced_access_open;
    let rotate = state.clone();
    let extra = state.clone();
    let diag_state = state.clone();
    stack(
        "settings-content-stack",
        vec![
            card(
                scope,
                context.clone(),
                "Security health",
                vec![
                    paragraph(health.badge, health.label),
                    paragraph("muted", health.next_step),
                    action(
                        scope,
                        context.clone(),
                        "security-diagnostics-toggle",
                        "Diagnostics",
                        "secondary security-diagnostics-button",
                        true,
                        move || {
                            diagnostics.revise(|value| {
                                *value = !*value;
                            })
                        },
                    ),
                    reactive(diagnostics, move |scope, open| {
                        if !open {
                            return empty();
                        }
                        let context = diag_state.context.clone();
                        let basis = context.state_store.read(|store| {
                            store.active_authority().and_then(|issuer| {
                                capability_issuer_basis(
                                    &diag_state.realm,
                                    &store.realm_current_state_entries(&diag_state.realm),
                                    &issuer,
                                )
                            })
                        });
                        card(
                            scope,
                            context,
                            "Diagnostics",
                            vec![
                                paragraph(
                                    "muted",
                                    "Only verified governing Station lineage and accepted submission state are shown here.",
                                ),
                                plain(
                                    basis
                                        .map(|basis| {
                                            format!(
                                                "generation {} · {}",
                                                basis.authority_generation,
                                                basis.authority_event_ref
                                            )
                                        })
                                        .unwrap_or_else(|| {
                                            VERIFIED_AUTHORITY_ROOT_UNAVAILABLE.into()
                                        }),
                                ),
                            ],
                        )
                    }),
                ],
            ),
            card(
                scope,
                context.clone(),
                "Encryption keys",
                vec![
                    paragraph(
                        "muted",
                        "Keys update automatically when membership changes. You can also refresh them now.",
                    ),
                    action(
                        scope,
                        context.clone(),
                        "rotate-realm-epoch",
                        "Refresh keys",
                        "secondary",
                        true,
                        move || rotate.rotate(),
                    ),
                ],
            ),
            card(
                scope,
                context.clone(),
                "Advanced permissions",
                vec![
                    paragraph(
                        "muted",
                        "Grant individual capabilities or Realm administrator access.",
                    ),
                    action(
                        scope,
                        context.clone(),
                        "advanced-access-toggle",
                        "Manage permissions",
                        "secondary",
                        true,
                        move || {
                            advanced.revise(|value| {
                                *value = !*value;
                            })
                        },
                    ),
                    reactive(advanced, move |scope, open| {
                        if open {
                            advanced_view(scope, &extra)
                        } else {
                            empty()
                        }
                    }),
                ],
            ),
        ],
    )
}
fn advanced_view(scope: &Scope, state: &AdminPage) -> View {
    let context = state.context.clone();
    let grant = state.clone();
    let revoke = state.clone();
    let grant_admin = state.clone();
    let revoke_admin = state.clone();
    let pending = state.capability_grant_pending;
    let enabled = scope.bond(move || !pending.get());
    let temporal = state.cap_constraint_kind;
    let before = state.cap_temporal_not_before;
    let expires = state.cap_temporal_expires_at;
    stack(
        "security-advanced-controls",
        vec![
            card(
                scope,
                context.clone(),
                "Capability grant / revoke",
                vec![
                    input(
                        scope,
                        context.clone(),
                        "cap-grant-id-input",
                        "Grant ID (required for revoke only)",
                        state.cap_grant_id,
                        true,
                    ),
                    input(
                        scope,
                        context.clone(),
                        "cap-grant-tag-input",
                        "Capability tag (action / scope)",
                        state.cap_tag,
                        true,
                    ),
                    input(
                        scope,
                        context.clone(),
                        "cap-grant-subject-input",
                        "Subject DID (grantee — required for grant)",
                        state.cap_subject,
                        true,
                    ),
                    input(
                        scope,
                        context.clone(),
                        "cap-revoke-reason-input",
                        "Revoke reason (optional)",
                        state.cap_revoke_reason,
                        true,
                    ),
                    choice(
                        scope,
                        context.clone(),
                        "cap-constraint-kind-select",
                        "Constraint family",
                        temporal,
                        ["none", "temporal", "quota", "scope_limitation"]
                            .into_iter()
                            .map(|value| (value.to_owned(), value.to_owned()))
                            .collect(),
                        true,
                        move |next| {
                            temporal.revise(|value| {
                                *value = next;
                            })
                        },
                    ),
                    input(
                        scope,
                        context.clone(),
                        "cap-constraint-not-before-input",
                        "not_before (RFC 3339, optional)",
                        before,
                        true,
                    ),
                    input(
                        scope,
                        context.clone(),
                        "cap-constraint-expires-at-input",
                        "expires_at (RFC 3339, optional)",
                        expires,
                        true,
                    ),
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "cap-grant-submit-button",
                                "realm_admin.grant_capability_move",
                                "primary",
                                enabled,
                                move || grant.grant(),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "cap-revoke-submit-button",
                                "realm_admin.revoke_capability_move",
                                "secondary",
                                enabled,
                                move || revoke.revoke(),
                            ),
                        ],
                    ),
                ],
            ),
            card(
                scope,
                context.clone(),
                "Realm administrator",
                vec![
                    input(
                        scope,
                        context.clone(),
                        "realm-admin-subject-input",
                        "Subject",
                        state.admin_subject_id,
                        true,
                    ),
                    input(
                        scope,
                        context.clone(),
                        "realm-admin-grant-id-input",
                        "Grant ID",
                        state.admin_grant_id,
                        true,
                    ),
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "realm-admin-grant-button",
                                "realm_admin.admin_grant_button",
                                "primary",
                                true,
                                move || grant_admin.grant_admin(),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "realm-admin-revoke-button",
                                "realm_admin.admin_revoke_button",
                                "secondary",
                                true,
                                move || revoke_admin.revoke_admin(),
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )
}
fn repair_view(scope: &Scope, state: &AdminPage) -> View {
    let context = state.context.clone();
    let archive = state.archive_confirm_open;
    let destroy = state.destroy_confirm_open;
    let leave = state.leave_confirm_open;
    let confirmation_text = state.danger_confirm_text;
    let mut records = Vec::new();
    for record in context
        .state_store
        .read(|store| store.move_submissions_for_realm(&state.realm))
    {
        let mut details = vec![
            line(
                "event-head",
                vec![
                    plain(record.kind),
                    paragraph(record.state.badge_class(), record.state.label_zh()),
                ],
            ),
            paragraph("muted", short_protocol_id(&record.move_id)),
        ];
        if let Some(event) = record.event_id {
            details.push(paragraph("muted", short_protocol_id(&event)));
        }
        if record.state.is_failed() {
            let open = state.move_detail_open;
            let target = record.move_id.clone();
            let selected = target.clone();
            details.push(action(
                scope,
                context.clone(),
                "move-failure-detail-toggle",
                "Failure detail",
                "secondary",
                true,
                move || {
                    open.revise(|current| {
                        *current = if current.as_deref() == Some(target.as_str()) {
                            None
                        } else {
                            Some(target.clone())
                        }
                    });
                },
            ));
            let reason = record.reason.clone();
            let head = record.observed_stream_head.clone();
            let submitted = record.submitted_at;
            details.push(reactive(open, move |_, active| {
                if active.as_deref() != Some(selected.as_str()) {
                    return empty();
                }
                let mut lines = vec![paragraph(
                    "",
                    format!("reason: {}", reason.as_deref().unwrap_or("(none reported)")),
                )];
                if let Some(head) = &head {
                    lines.push(paragraph("", format!("observed stream head: {head}")));
                }
                lines.push(paragraph("", format!("submitted_at: {submitted}")));
                stack("muted move-failure-detail", lines)
            }));
        }
        records.push(stack("event move-submission-row", details));
    }
    let danger_state = state.clone();
    let leave_state = state.clone();
    let reason = state.destroy_reason;
    let source = scope.bond(move || (archive.get(), destroy.get()));
    let danger = reactive(source, move |scope, (is_archive, is_destroy)| {
        if !is_archive && !is_destroy {
            return empty();
        }
        let state = danger_state.clone();
        let context = state.context.clone();
        let submit = state.clone();
        let target = state.realm.clone();
        let matches = scope.bond(move || confirmation_text.get().trim() == target.trim());
        let mut body = vec![
            paragraph(
                "",
                if is_destroy {
                    "Destroying a Realm is destructive and may make its realm, members, policy, and encrypted history unavailable. This should only be used when the operator has verified the recovery and audit path."
                } else {
                    "Archiving removes the Realm from active collaboration flows. Members may lose the normal working entry point until an operator restores or migrates it."
                },
            ),
            input(
                scope,
                context.clone(),
                "realm-danger-confirm-input",
                "Type the Realm ID to confirm",
                confirmation_text,
                true,
            ),
        ];
        if is_destroy {
            body.push(input(
                scope,
                context.clone(),
                "realm-destroy-reason-input",
                "Audit reason",
                reason,
                true,
            ));
        }
        body.push(action(
            scope,
            context.clone(),
            "realm-danger-confirm-submit",
            if is_destroy {
                "Destroy Realm"
            } else {
                "Archive Realm"
            },
            "destructive",
            matches,
            move || submit.danger(),
        ));
        confirmation(
            scope,
            context,
            "realm-danger-confirm-modal",
            if is_destroy {
                "Destroy Realm"
            } else {
                "Archive Realm"
            },
            stack("modal-body", body),
            move || {
                archive.revise(|value| {
                    *value = false;
                });
                destroy.revise(|value| {
                    *value = false;
                });
                confirmation_text.revise(|value| value.clear());
            },
        )
    });
    let leave_modal = reactive(leave, move |scope, open| {
        if !open {
            return empty();
        }
        let state = leave_state.clone();
        let context = state.context.clone();
        let submit = state.clone();
        confirmation(
            scope,
            context.clone(),
            "leave-realm-modal",
            "Leave Realm",
            stack(
                "modal-body",
                vec![
                    paragraph(
                        "muted",
                        "You will lose access to this Realm. You can rejoin through a new invitation.",
                    ),
                    action(
                        scope,
                        context,
                        "leave-realm-confirm-button",
                        "realm_admin.leave_realm",
                        "destructive",
                        true,
                        move || submit.leave(),
                    ),
                ],
            ),
            move || {
                leave.revise(|value| {
                    *value = false;
                })
            },
        )
    });
    stack(
        "settings-content-stack",
        vec![
            card(scope, context.clone(), "Recent Move submissions", records),
            card(
                scope,
                context.clone(),
                "Ownership",
                vec![
                    paragraph("muted", VERIFIED_AUTHORITY_ROOT_UNAVAILABLE),
                    action(
                        scope,
                        context.clone(),
                        "owner-transfer-button",
                        "Transfer ownership",
                        "destructive",
                        governance_authoring_gate().is_ok(),
                        || {},
                    ),
                    action(
                        scope,
                        context.clone(),
                        "authority-reset-button",
                        "Reset authority generation",
                        "destructive",
                        false,
                        || {},
                    ),
                ],
            ),
            card(
                scope,
                context.clone(),
                "Leave Realm",
                vec![action(
                    scope,
                    context.clone(),
                    "leave-realm-button",
                    "realm_admin.leave_realm",
                    "secondary",
                    true,
                    move || {
                        leave.revise(|value| {
                            *value = true;
                        })
                    },
                )],
            ),
            card(
                scope,
                context.clone(),
                "Danger Zone",
                vec![line(
                    "actions",
                    vec![
                        action(
                            scope,
                            context.clone(),
                            "archive-realm-button",
                            "realm_admin.archive_realm",
                            "destructive",
                            true,
                            move || {
                                confirmation_text.revise(|value| value.clear());
                                destroy.revise(|value| {
                                    *value = false;
                                });
                                archive.revise(|value| {
                                    *value = true;
                                });
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "destroy-realm-button",
                            "realm_admin.destroy_realm",
                            "destructive",
                            true,
                            move || {
                                confirmation_text.revise(|value| value.clear());
                                archive.revise(|value| {
                                    *value = false;
                                });
                                destroy.revise(|value| {
                                    *value = true;
                                });
                            },
                        ),
                    ],
                )],
            ),
            danger,
            leave_modal,
        ],
    )
}
