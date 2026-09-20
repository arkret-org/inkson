//! Network commands for the Realm admin panel.
//!
//! Every write the panel can issue lives here as one named command. The rsx
//! above keeps the synchronous half — read the form, validate it, close the
//! dialog — and hands the command a value; it no longer carries a hundred-line
//! `async move` block inside an `onclick`.

use super::*;
use crate::state::LocalStateStore;

/// Signals the admin panel's writes fold their outcome back into.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct RealmAdminController {
    pub(super) status_msg: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) state_store: SyncSignal<LocalStateStore>,
    pub(super) gov_transfer_target: Signal<String>,
    pub(super) gov_transfer_acceptance: Signal<String>,
    pub(super) metadata_alias: Signal<String>,
    pub(super) admin_grant_id: Signal<String>,
}

impl RealmAdminController {
    /// `ak.realm.owner.transfer`. The payload is built and validated in the
    /// dialog; by the time it reaches here the successor and their acceptance
    /// proof are already fixed.
    pub(super) fn transfer_owner(
        mut self,
        base_url: String,
        api_token: String,
        actor_id: String,
        payload: arkret_sdk::RealmOwnerTransferPayload,
        successor_label: String,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::transfer_realm_owner(&sub, &actor_id, payload)
                        .await
                },
            )
            .await
            {
                Ok(resp) => {
                    self.gov_transfer_target.set(String::new());
                    self.gov_transfer_acceptance.set(String::new());
                    self.status_msg.set(format!(
                        "owner transfer submitted: event_id={} — once sealed, {} is the root \
                         controller and this account is demoted",
                        short_protocol_id(&resp.event_id),
                        short_protocol_id(&successor_label),
                    ));
                }
                Err(err) => self.status_msg.set(governance_failure_message(
                    "owner transfer failed",
                    &err.display(),
                )),
            }
        });
    }

    /// `ak.realm.authority.reset` — voids every grant issued under the current
    /// generation once sealed.
    pub(super) fn reset_authority(
        mut self,
        base_url: String,
        api_token: String,
        actor_id: String,
        payload: arkret_sdk::RealmAuthorityResetPayload,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::reset_realm_authority(&sub, &actor_id, payload)
                        .await
                },
            )
            .await
            {
                Ok(resp) => self.status_msg.set(format!(
                    "authority reset submitted: event_id={} — every grant issued under the \
                     previous generation is void once sealed",
                    short_protocol_id(&resp.event_id),
                )),
                Err(err) => self.status_msg.set(governance_failure_message(
                    "authority reset failed",
                    &err.display(),
                )),
            }
        });
    }

    /// Realm or Space profile update, optionally setting the Realm alias in
    /// the same governance checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn save_metadata(
        mut self,
        base_url: String,
        api_token: String,
        actor_id: String,
        subject: MetadataWriteSubject,
        patch: Value,
        alias: String,
        accepted: AcceptedRealmProfile,
    ) {
        spawn(async move {
            let MetadataWriteSubject {
                home_realm_id,
                subject_id,
                kind,
                event_kind,
                updates_alias,
                causal_refs,
            } = subject;
            let submit_home_realm_id = home_realm_id.clone();
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    let digest_suite = sub
                        .refresh_realm_governance_frontier(&submit_home_realm_id)
                        .await?;
                    let profile_result = match kind {
                        RealmTreeNodeKind::Realm => {
                            crate::transport::realm_write::update_realm_metadata(
                                &sub,
                                &submit_home_realm_id,
                                &actor_id,
                                digest_suite,
                                patch,
                                causal_refs,
                            )
                            .await
                        }
                        RealmTreeNodeKind::Space => {
                            crate::transport::realm_write::update_space_metadata(
                                &sub,
                                &submit_home_realm_id,
                                &subject_id,
                                &actor_id,
                                patch,
                                causal_refs,
                            )
                            .await
                        }
                    }?;
                    if kind == RealmTreeNodeKind::Realm && !alias.is_empty() {
                        crate::transport::realm_write::set_realm_alias(
                            &sub,
                            &submit_home_realm_id,
                            &actor_id,
                            Some(&alias),
                        )
                        .await?;
                    }
                    Ok::<_, anyhow::Error>(profile_result)
                },
            )
            .await
            {
                Ok(_) => {
                    if kind == RealmTreeNodeKind::Realm {
                        crate::views::realm_admin::metadata::store_accepted_realm_profile(
                            &mut self.state_store.write(),
                            &home_realm_id,
                            &accepted.title,
                            accepted.summary.as_deref(),
                            accepted.avatar_blob_ref.as_deref(),
                        );
                    }
                    self.status_msg.set(if updates_alias {
                        format!("{event_kind} profile and Realm alias updated")
                    } else {
                        format!("{event_kind} profile updated")
                    });
                }
                Err(err) => self
                    .status_msg
                    .set(format!("profile update failed: {}", err.display())),
            }
        });
    }

    pub(super) fn remove_alias(
        mut self,
        base_url: String,
        api_token: String,
        actor_id: String,
        home_realm_id: String,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::set_realm_alias(
                        &sub,
                        &home_realm_id,
                        &actor_id,
                        None,
                    )
                    .await
                },
            )
            .await
            {
                Ok(_) => {
                    self.metadata_alias.set(String::new());
                    self.status_msg.set("Realm alias removed".to_owned());
                }
                Err(error) => self
                    .status_msg
                    .set(format!("alias removal failed: {}", error.display())),
            }
        });
    }

    /// Join rule, history-access tightening and the principal-admission join
    /// policy, all under one governance checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_policy(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        rule: String,
        tighten_access: bool,
        join_policy: Option<Value>,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    let digest_suite = sub.refresh_realm_governance_frontier(&realm_id).await?;
                    crate::transport::realm_write::set_realm_policy_events(
                        &sub,
                        &realm_id,
                        &actor_id,
                        digest_suite,
                        &rule,
                        tighten_access,
                        join_policy,
                    )
                    .await
                },
            )
            .await
            {
                Ok(resp) => self.status_msg.set(format!(
                    "policy: join={}, history_access_tightened={}",
                    resp.join_rule, resp.history_access_tightened
                )),
                Err(err) => self
                    .status_msg
                    .set(format!("policy failed: {}", err.display())),
            }
        });
    }

    /// Forced MLS self-update commit. The identity guard already ran in the
    /// handler, so the account handed over here is the one that clicked.
    pub(super) fn rotate_mls_epoch(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        device_id: String,
        account: crate::config::ActiveAccountContext,
        secure_store: std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    ) {
        spawn(async move {
            let local_state = self.state_store.read().clone();
            let built = crate::mls::runtime::force_epoch_rotation_commit(
                &local_state,
                secure_store.as_ref(),
                &realm_id,
                &account.authority,
                &account.device_id,
            )
            .map_err(|err| err.user_message());
            let (commit_envelope, snapshot, previous_governance_binding) = match built {
                Ok(parts) => parts,
                Err(err) => {
                    self.status_msg.set(format!("rotate failed: {err}"));
                    return;
                }
            };
            let schedule_hash = commit_envelope.commit_digest.clone();
            let commit_event = match crate::mls::group_events::mls_commit_event_from_store(
                &local_state,
                &realm_id,
                &actor_id,
                &schedule_hash,
                &commit_envelope,
                &previous_governance_binding,
            )
            .await
            {
                Ok(event) => event,
                Err(err) => {
                    self.status_msg.set(format!("rotate failed: {err}"));
                    return;
                }
            };
            let next_epoch = commit_envelope.epoch;
            match crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                api.event_submitter()?.submit_sdk_event(&commit_event).await
            })
            .await
            {
                Ok(accepted) => {
                    // Persist-on-accept: only advance the local snapshot after
                    // the server accepted the ak.mls.commit, and bind it to the
                    // id the server accepted.
                    let commit_event_id = match arkret_sdk::EventId::new(accepted.event_id.clone())
                    {
                        Ok(event_id) => event_id,
                        Err(error) => {
                            self.status_msg.set(format!(
                                "rotate accepted but its Event id is invalid: {error}"
                            ));
                            return;
                        }
                    };
                    if let Err(error) = self
                        .state_store
                        .write()
                        .record_mls_group_state_ref_for_effective_scope(
                            realm_id.clone(),
                            None,
                            snapshot.group_id.as_str(),
                            snapshot.epoch,
                            commit_event_id,
                        )
                    {
                        self.status_msg.set(format!(
                            "rotate accepted but MLS reference persistence failed: {error}"
                        ));
                        return;
                    }
                    if let Err(error) = self
                        .state_store
                        .write()
                        .save_mls_checkpoint(realm_id.clone(), snapshot)
                    {
                        self.status_msg
                            .set(format!("MLS snapshot persist failed: {error}"));
                        return;
                    }
                    // A self-update is also the spec-defined recovery commit
                    // when a historical membership transition changed the
                    // frontier without changing the current MLS roster. Never
                    // clear the send gate merely because the Event is
                    // effective: require this accepted Commit and exact
                    // complete-hint/MLS-roster agreement.
                    let roster_aligned = {
                        let store = self.state_store.read();
                        super::super::members_panel::admission::
                            realm_mls_roster_matches_complete_membership_hint(
                                &store,
                                secure_store.as_ref(),
                                &realm_id,
                                &actor_id,
                                &device_id,
                            )
                    };
                    if roster_aligned {
                        let mut store = self.state_store.write();
                        store.resolve_member_add_mls_bindings(&realm_id);
                        store.resolve_member_remove_mls_bindings(&realm_id);
                    }
                    self.status_msg
                        .set(format!("rotated to epoch {next_epoch}"));
                }
                Err(err) => self
                    .status_msg
                    .set(format!("rotate failed: {}", err.display())),
            }
        });
    }

    pub(super) fn leave_realm(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
    ) {
        spawn(async move {
            let realm_for_msg = realm_id.clone();
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::leave_realm(&sub, &realm_id, &actor_id).await
                },
            )
            .await
            {
                Ok(_) => {
                    self.state_store
                        .write()
                        .forget_realm_tree_projection(&realm_for_msg);
                    self.sync_cursor.set(String::new());
                    self.status_msg
                        .set(format!("left {realm_for_msg}; local cache cleared"));
                }
                Err(err) => self
                    .status_msg
                    .set(format!("leave failed: {}", err.display())),
            }
        });
    }

    /// Submit a locally built capability Event and report it by op id.
    ///
    /// `report_durable_queue` exists because only the grant path tells the
    /// operator that a durably queued submit will retry; revoke reports the
    /// same condition as a plain failure. Both behaviours are preserved here
    /// rather than silently unified.
    pub(super) fn submit_capability_event(
        mut self,
        base_url: String,
        api_token: String,
        envelope: crate::operation::LocalOperation,
        op_id: String,
        event_kind: &'static str,
        failure_prefix: &'static str,
        report_durable_queue: bool,
    ) {
        spawn(async move {
            match crate::transport::auth::with_authed_api(&base_url, api_token, |api| async move {
                api.event_submitter()?.submit_sdk_event(&envelope).await
            })
            .await
            {
                Ok(resp) => self.status_msg.set(format!(
                    "{event_kind} event {}: event_id={}",
                    short_protocol_id(&op_id),
                    short_protocol_id(&resp.event_id)
                )),
                Err(err)
                    if report_durable_queue
                        && crate::event_submit::is_durably_queued_error(err.inner()) =>
                {
                    self.status_msg.set(format!(
                        "{event_kind} event {} queued for retry",
                        short_protocol_id(&op_id)
                    ));
                }
                Err(err) => self
                    .status_msg
                    .set(format!("{failure_prefix} submit failed: {}", err.display())),
            }
        });
    }

    /// `ak.realm.admin` grant. The grant id is minted from the accepted
    /// Event, so the revoke field fills itself in on success.
    pub(super) fn grant_realm_admin(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        subject: arkret_sdk::AccountId,
        issuer_root_basis: crate::operation::ak_ops::IssuerRootBasis,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::grant_realm_admin(
                        &sub,
                        &realm_id,
                        &actor_id,
                        &subject,
                        issuer_root_basis,
                    )
                    .await
                },
            )
            .await
            {
                Ok(resp) => {
                    if let Ok(event_id) = arkret_sdk::EventId::new(resp.event_id.clone()) {
                        self.admin_grant_id
                            .set(arkret_sdk::GrantId::from_event_id(&event_id).to_string());
                    }
                    self.status_msg.set(format!(
                        "granted ak.realm.admin: event_id={}",
                        short_protocol_id(&resp.event_id)
                    ));
                }
                Err(err) => self
                    .status_msg
                    .set(format!("set admin failed: {}", err.display())),
            }
        });
    }

    pub(super) fn revoke_realm_admin(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        grant_id: String,
    ) {
        spawn(async move {
            match crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    crate::transport::realm_write::revoke_realm_admin(
                        &sub,
                        &realm_id,
                        &actor_id,
                        &grant_id,
                        Some("admin_revoke"),
                    )
                    .await
                },
            )
            .await
            {
                Ok(resp) => self.status_msg.set(format!(
                    "revoked ak.realm.admin: event_id={}",
                    short_protocol_id(&resp.event_id)
                )),
                Err(err) => self
                    .status_msg
                    .set(format!("revoke admin failed: {}", err.display())),
            }
        });
    }

    /// Archive or destroy. They share a dialog, a confirmation and a status
    /// line shape, and differ only in the Event they author.
    pub(super) fn archive_or_destroy_realm(
        mut self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        reason: String,
        destroy: bool,
    ) {
        spawn(async move {
            let realm_for_msg = realm_id.clone();
            let result = crate::transport::auth::with_event_submitter(
                &base_url,
                api_token,
                |sub| async move {
                    if destroy {
                        let reason = if reason.is_empty() {
                            "operator_request".to_owned()
                        } else {
                            reason
                        };
                        crate::transport::realm_write::destroy_realm(
                            &sub, &realm_id, &actor_id, &reason,
                        )
                        .await
                    } else {
                        crate::transport::realm_write::archive_realm(&sub, &realm_id, &actor_id)
                            .await
                    }
                },
            )
            .await;
            match result {
                Ok(_) if destroy => self
                    .status_msg
                    .set(format!("destroyed {}", short_protocol_id(&realm_for_msg))),
                Ok(_) => self
                    .status_msg
                    .set(format!("archive event submitted ({realm_for_msg})")),
                Err(err) if destroy => self
                    .status_msg
                    .set(format!("destroy failed: {}", err.display())),
                Err(err) => self
                    .status_msg
                    .set(format!("archive failed: {}", err.display())),
            }
        });
    }
}

/// Which subject a metadata save is addressed to, and how it reports itself.
pub(super) struct MetadataWriteSubject {
    pub(super) home_realm_id: String,
    pub(super) subject_id: String,
    pub(super) kind: RealmTreeNodeKind,
    pub(super) event_kind: &'static str,
    pub(super) updates_alias: bool,
    pub(super) causal_refs: Vec<arkret_sdk::Hash>,
}

/// The values a successful Realm profile save writes back into local state.
pub(super) struct AcceptedRealmProfile {
    pub(super) title: String,
    pub(super) summary: Option<String>,
    pub(super) avatar_blob_ref: Option<String>,
}

/// Append the operator guidance for a known authority-root rejection to the
/// raw error text. Both governance commands report failures this way.
fn governance_failure_message(prefix: &str, error_text: &str) -> String {
    let hint = governance_failure_hint(error_text)
        .map(|hint| format!(" — {hint}"))
        .unwrap_or_default();
    format!("{prefix}: {error_text}{hint}")
}
