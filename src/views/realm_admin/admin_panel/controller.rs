//! Network commands for the Realm admin panel.
//!
//! Every write the panel can issue lives here as one named command. The rsx
//! above keeps the synchronous half — read the form, validate it, close the
//! dialog — and hands the command a value; it no longer carries a hundred-line
//! `async move` block inside an `onclick`.

use glory::Cage;

use super::*;
use crate::presentation::SharedStateStore;

/// Signals the admin panel's writes fold their outcome back into.
#[derive(Clone)]
pub(super) struct RealmAdminController {
    pub(super) owner: glory::ui::WeakScope,
    pub(super) status_msg: Cage<String>,
    pub(super) sync_cursor: Cage<String>,
    pub(super) state_store: SharedStateStore,
    pub(super) metadata_alias: Cage<String>,
    pub(super) admin_grant_id: Cage<String>,
    pub(super) capability_grant_pending: Cage<bool>,
    pub(super) capability_grant_id: Cage<String>,
}

impl RealmAdminController {
    /// Realm or Space profile update, optionally setting the Realm alias in
    /// the same governance checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn save_metadata(
        self,
        base_url: String,
        api_token: String,
        actor_id: String,
        subject: MetadataWriteSubject,
        patch: Value,
        alias: String,
        accepted: AcceptedRealmProfile,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                let MetadataWriteSubject {
                    home_realm_id,
                    subject_id,
                    kind,
                    event_kind,
                    updates_alias,
                } = subject;
                let submit_home_realm_id = home_realm_id.clone();
                match crate::transport::auth::with_event_submitter(
                    &base_url,
                    api_token,
                    |sub| async move {
                        // The immutable Realm id fixes the digest suite; current
                        // governance and admission remain Station decisions.
                        let digest_suite = arkret_sdk::RealmId::new(submit_home_realm_id.clone())?
                            .digest_suite_code()
                            .digest_suite();
                        let profile_result = match kind {
                            RealmTreeNodeKind::Realm => {
                                crate::transport::realm_write::update_realm_metadata(
                                    &sub,
                                    &submit_home_realm_id,
                                    &actor_id,
                                    digest_suite,
                                    patch,
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
                            self.state_store.write(|store| {
                                crate::views::realm_admin::metadata::store_accepted_realm_profile(
                                    store,
                                    &home_realm_id,
                                    &accepted.title,
                                    accepted.summary.as_deref(),
                                    accepted.avatar_blob_ref.as_deref(),
                                )
                            });
                        }
                        self.status_msg.revise(|value| {
                            *value = if updates_alias {
                                format!("{event_kind} profile and Realm alias updated")
                            } else {
                                format!("{event_kind} profile updated")
                            };
                        });
                    }
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("profile update failed: {}", err.display());
                    }),
                }
            });
        };
    }

    pub(super) fn remove_alias(
        self,
        base_url: String,
        api_token: String,
        actor_id: String,
        home_realm_id: String,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
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
                        self.metadata_alias.revise(|value| {
                            *value = String::new();
                        });
                        self.status_msg.revise(|value| {
                            *value = "Realm alias removed".to_owned();
                        });
                    }
                    Err(error) => self.status_msg.revise(|value| {
                        *value = format!("alias removal failed: {}", error.display());
                    }),
                }
            });
        };
    }

    /// Join rule, history-access tightening and the principal-admission join
    /// policy, all under one governance checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_policy(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        rule: String,
        tighten_access: bool,
        join_policy: Option<Value>,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                match crate::transport::auth::with_event_submitter(
                    &base_url,
                    api_token,
                    |sub| async move {
                        // Do not resurrect the retired Seal frontier to select a
                        // digest suite already encoded by the typed Realm id.
                        let digest_suite = arkret_sdk::RealmId::new(realm_id.clone())?
                            .digest_suite_code()
                            .digest_suite();
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
                    Ok(resp) => self.status_msg.revise(|value| {
                        *value = format!(
                            "policy: join={}, history_access_tightened={}",
                            resp.join_rule, resp.history_access_tightened
                        );
                    }),
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("policy failed: {}", err.display());
                    }),
                }
            });
        };
    }

    /// Forced MLS self-update commit. The identity guard already ran in the
    /// handler, so the account handed over here is the one that clicked.
    pub(super) fn rotate_mls_epoch(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        device_id: String,
        account: crate::config::ActiveAccountContext,
        secure_store: std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                let built = self
                    .state_store
                    .read(|store| {
                        crate::mls::runtime::force_epoch_rotation_commit(
                            store,
                            secure_store.as_ref(),
                            &realm_id,
                            &account.authority,
                            &account.device_id,
                        )
                    })
                    .map_err(|err| err.user_message());
                let staged = match built {
                    Ok(staged) => staged,
                    Err(err) => {
                        self.status_msg.revise(|value| {
                            *value = format!("rotate failed: {err}");
                        });
                        return;
                    }
                };
                let commit_event = match self.state_store.read(|store| {
                    crate::mls::group_events::mls_commit_event_from_store(
                        store,
                        &realm_id,
                        &actor_id,
                        &staged.envelope,
                    )
                }) {
                    Ok(event) => event,
                    Err(err) => {
                        self.status_msg.revise(|value| {
                            *value = format!("rotate failed: {err}");
                        });
                        return;
                    }
                };
                let next_epoch = staged.envelope.epoch;
                let state_store_handle = self.state_store.handle();
                let submit_device_id = account.device_id.clone();
                match crate::transport::auth::with_authed_api(
                    &base_url,
                    api_token,
                    |api| async move {
                        let submitter = api.event_submitter()?;
                        let authored = submitter
                            .author_for_direct_submission(&commit_event)
                            .await?;
                        submitter
                            .submit_mls_commit(
                                authored,
                                Vec::new(),
                                submit_device_id,
                                Vec::new(),
                                &state_store_handle,
                                staged.staged_checkpoint,
                            )
                            .await
                    },
                )
                .await
                {
                    Ok(_) => {
                        // A self-update is also the spec-defined recovery commit
                        // when a historical membership transition changed the
                        // frontier without changing the current MLS roster. Never
                        // clear the send gate merely because the Event is
                        // effective: require this accepted Commit and exact
                        // complete-hint/MLS-roster agreement.
                        let roster_aligned = self.state_store.read(|store| {
                            crate::mls::admission_reconcile::
                            realm_mls_roster_matches_complete_membership_hint(
                                store,
                                secure_store.as_ref(),
                                &realm_id,
                                &actor_id,
                                &device_id,
                            )
                        });
                        if roster_aligned {
                            self.state_store.write(|store| {
                                store.resolve_member_add_mls_bindings(&realm_id);
                                store.resolve_member_remove_mls_bindings(&realm_id);
                            });
                        }
                        self.status_msg.revise(|value| {
                            *value = format!("rotated to epoch {next_epoch}");
                        });
                    }
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("rotate failed: {}", err.display());
                    }),
                }
            });
        };
    }

    pub(super) fn leave_realm(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
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
                            .write(|store| store.forget_realm_tree_projection(&realm_for_msg));
                        self.sync_cursor.revise(|value| {
                            *value = String::new();
                        });
                        self.status_msg.revise(|value| {
                            *value = format!("left {realm_for_msg}; local cache cleared");
                        });
                    }
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("leave failed: {}", err.display());
                    }),
                }
            });
        };
    }

    /// Admit one capability grant at a time and expose its actual outcome.
    pub(super) fn submit_capability_grant(
        self,
        base_url: String,
        api_token: String,
        envelope: crate::operation::LocalOperation,
    ) {
        let page_owner = self.owner.clone();
        if self.capability_grant_pending.get() {
            return;
        }
        self.capability_grant_pending.revise(|value| {
            *value = true;
        });
        self.status_msg.revise(|value| {
            *value = crate::i18n::tr("realm_admin.grant_capability_pending");
        });
        let op_id = envelope.local_operation_id().to_string();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                match crate::transport::auth::with_authed_api(
                    &base_url,
                    api_token,
                    |api| async move { api.event_submitter()?.submit_sdk_event(&envelope).await },
                )
                .await
                {
                    Ok(resp) => {
                        if let Ok(event_id) = arkret_sdk::EventId::new(resp.event_id.clone()) {
                            let grant_id =
                                arkret_sdk::GrantId::from_event_id(&event_id).to_string();
                            self.capability_grant_id.revise(|value| {
                                *value = grant_id.clone();
                            });
                            self.status_msg.revise(|value| {
                                *value = format!(
                                    "{} {}",
                                    crate::i18n::tr("realm_admin.capability_granted"),
                                    short_protocol_id(&grant_id)
                                );
                            });
                        } else {
                            self.status_msg.revise(|value| {
                                *value = format!(
                                    "capability grant accepted: event_id={}",
                                    short_protocol_id(&resp.event_id)
                                );
                            });
                        }
                    }
                    Err(err) if crate::event_submit::is_durably_queued_error(err.inner()) => {
                        self.status_msg.revise(|value| {
                            *value = format!(
                                "capability grant {} queued for retry",
                                short_protocol_id(&op_id)
                            );
                        });
                    }
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("capability grant failed: {}", err.display());
                    }),
                }
                self.capability_grant_pending.revise(|value| {
                    *value = false;
                });
            });
        };
    }

    /// `ak.realm.admin` grant. The grant id is minted from the accepted
    /// Event, so the revoke field fills itself in on success.
    pub(super) fn grant_realm_admin(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        subject: arkret_sdk::AccountId,
        issuer_root_basis: crate::operation::ak_ops::IssuerRealmAuthorityBasis,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                match crate::transport::auth::with_event_submitter(
                    &base_url,
                    api_token,
                    |sub| async move {
                        crate::transport::realm_write::grant_realm_admin(
                            &sub,
                            &realm_id,
                            &actor_id,
                            &subject,
                            &issuer_root_basis,
                        )
                        .await
                    },
                )
                .await
                {
                    Ok(resp) => {
                        if let Ok(event_id) = arkret_sdk::EventId::new(resp.event_id.clone()) {
                            self.admin_grant_id.revise(|value| {
                                *value = arkret_sdk::GrantId::from_event_id(&event_id).to_string();
                            });
                        }
                        self.status_msg.revise(|value| {
                            *value = format!(
                                "granted ak.realm.admin: event_id={}",
                                short_protocol_id(&resp.event_id)
                            );
                        });
                    }
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("set admin failed: {}", err.display());
                    }),
                }
            });
        };
    }

    /// Read the target Grant and its exact revision from the governing
    /// Station, then author one capability revoke from that same row. Missing,
    /// duplicate or cross-Realm rows fail before Event construction.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn revoke_capability_from_effective_row(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        subject: arkret_sdk::ActorId,
        grant_id: String,
        reason: Option<String>,
        status_label: &'static str,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
                match crate::transport::auth::with_event_submitter(
                    &base_url,
                    api_token,
                    |sub| async move {
                        let realm = arkret_sdk::RealmId::new(realm_id.clone())?;
                        let grants = crate::transport::realm_read::effective_grants(
                            sub.http(),
                            &realm,
                            &subject,
                        )
                        .await?;
                        let row = crate::operation::ak_ops::effective_grant_row_for_revoke(
                            &grants, &grant_id,
                        )?;
                        let event = crate::operation::ak_ops::capability_revoke_from_effective_row(
                            realm.as_str(),
                            &actor_id,
                            row,
                            reason.as_deref(),
                        )?
                        .build_sdk_event("inkson")?;
                        sub.submit_sdk_event(&event).await
                    },
                )
                .await
                {
                    Ok(resp) => self.status_msg.revise(|value| {
                        *value = format!(
                            "{status_label}: event_id={}",
                            short_protocol_id(&resp.event_id)
                        );
                    }),
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("{status_label} failed: {}", err.display());
                    }),
                }
            });
        };
    }

    /// Archive or destroy. They share a dialog, a confirmation and a status
    /// line shape, and differ only in the Event they author.
    pub(super) fn archive_or_destroy_realm(
        self,
        base_url: String,
        api_token: String,
        realm_id: String,
        actor_id: String,
        reason: String,
        destroy: bool,
    ) {
        let page_owner = self.owner.clone();
        if let Some(scope) = page_owner.upgrade() {
            super::super::super::settings::widgets::spawn(&scope, async move {
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
                    Ok(_) if destroy => self.status_msg.revise(|value| {
                        *value = format!("destroyed {}", short_protocol_id(&realm_for_msg));
                    }),
                    Ok(_) => self.status_msg.revise(|value| {
                        *value = format!("archive event submitted ({realm_for_msg})");
                    }),
                    Err(err) if destroy => self.status_msg.revise(|value| {
                        *value = format!("destroy failed: {}", err.display());
                    }),
                    Err(err) => self.status_msg.revise(|value| {
                        *value = format!("archive failed: {}", err.display());
                    }),
                }
            });
        };
    }
}

/// Which subject a metadata save is addressed to, and how it reports itself.
pub(super) struct MetadataWriteSubject {
    pub(super) home_realm_id: String,
    pub(super) subject_id: String,
    pub(super) kind: RealmTreeNodeKind,
    pub(super) event_kind: &'static str,
    pub(super) updates_alias: bool,
}

/// The values a successful Realm profile save writes back into local state.
pub(super) struct AcceptedRealmProfile {
    pub(super) title: String,
    pub(super) summary: Option<String>,
    pub(super) avatar_blob_ref: Option<String>,
}
