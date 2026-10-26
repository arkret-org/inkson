use std::rc::Rc;

use glory::Scope;
use glory::ui::Widget;

use super::data::*;
use super::helpers::*;
use super::model::*;
use crate::api_error::is_auth_expired_error;
use crate::i18n::{tr, tr_args};
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::transport::auth::authed_api_ready;
use crate::views::settings::widgets::*;

#[path = "realms/presentation.rs"]
mod presentation;
#[derive(Clone)]
struct BootstrapProgressStrings {
    accepted: String,
    created: String,
    canonical_policy: String,
    plaintext_services: String,
    mls_ready_local: String,
    signer_not_ready: String,
    create_failed: String,
    created_then_failed: String,
    mls_activation_failed: String,
    invalid_server_url: String,
    session_expired: String,
}

impl BootstrapProgressStrings {
    fn resolve() -> Self {
        Self {
            accepted: tr("setup.progress.accepted"),
            created: tr("setup.progress.created"),
            canonical_policy: tr("setup.progress.canonical_policy"),
            plaintext_services: tr("setup.progress.plaintext_services"),
            mls_ready_local: tr("setup.progress.mls_ready_local"),
            signer_not_ready: tr("setup.error.signer_not_ready"),
            create_failed: tr("setup.error.create_failed"),
            created_then_failed: tr("setup.error.created_then_failed"),
            mls_activation_failed: tr("setup.error.mls_activation_failed"),
            invalid_server_url: tr("setup.error.invalid_server_url"),
            session_expired: tr("setup.error.session_expired"),
        }
    }

    fn fill(template: &str, args: &[(&'static str, String)]) -> String {
        crate::i18n::substitute_args(template.to_owned(), args)
    }
}

/// Realm authoring becomes available once the session credential and secure
/// store have finished hydrating. The async authenticated-client provider used
/// by the submit path owns grant rotation, so UI readiness must not depend on a
/// synchronous snapshot of the persisted grant: that snapshot can briefly be
/// expired while the provider is rotating it in the background.
fn realm_create_available(
    has_session: bool,
    basics_ready: bool,
    boundary_ready: bool,
    secure_store_ready: bool,
    create_busy: bool,
    has_created_realm: bool,
) -> bool {
    has_session
        && basics_ready
        && boundary_ready
        && secure_store_ready
        && !create_busy
        && !has_created_realm
}

/// Recovery readiness has three states because `None` means the authoritative
/// server check has not completed (or could not complete), not that Recovery
/// is absent. Treating it as `false` makes a transient request race look like a
/// request to configure a second Recovery Key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptedRealmRecoveryGateState {
    Ready,
    Checking,
    Missing,
}

async fn create_initial_default_discussion(
    api: &crate::transport::TransportClient,
    realm_id: &str,
    actor: &str,
) -> anyhow::Result<String> {
    let founding_realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let submitter = api
        .event_submitter()?
        .for_founding_realm(founding_realm.clone());
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: founding_realm.clone(),
    };
    if submitter.creator_bootstrap_intent(&scope).await?.is_some() {
        return Ok(submitter
            .ensure_creator_realm_default_discussion(&founding_realm)
            .await?
            .into_string());
    }
    let create =
        crate::operation::ak_ops::initial_default_discussion_strand_create(realm_id, actor)?
            .build_sdk_event("inkson")?;
    let accepted = submitter.submit_sdk_event(&create).await?;
    let event_id = arkret_sdk::EventId::new(accepted.event_id).map_err(|error| {
        anyhow::anyhow!(tr_args(
            "setup.error.invalid_default_strand_id",
            &[("error", error.to_string())],
        ))
    })?;
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id).into_string();
    let set_default =
        crate::operation::ak_ops::realm_set_default_strand(realm_id, actor, &strand_id)?
            .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&set_default).await?;
    Ok(strand_id)
}

/// Accepted server policy is the account-level authority for Recovery setup.
/// Local metadata and the MLS backup marker remain useful offline fallbacks,
/// but a missing local cache must not contradict an already accepted policy.
fn encrypted_realm_recovery_gate_state(
    account_recovery_configured: Option<bool>,
    local_recovery_configured: bool,
    mls_recovery_backup_configured: bool,
) -> EncryptedRealmRecoveryGateState {
    if matches!(account_recovery_configured, Some(true))
        || local_recovery_configured
        || mls_recovery_backup_configured
    {
        EncryptedRealmRecoveryGateState::Ready
    } else if matches!(account_recovery_configured, Some(false)) {
        EncryptedRealmRecoveryGateState::Missing
    } else {
        EncryptedRealmRecoveryGateState::Checking
    }
}

impl super::SetupDraft {
    pub(super) fn create_realm(self, context: Rc<InksonContext>) {
        let token = context.token;
        let active_account = context.active_account;
        let selected_realm_id = context.selected_realm_id;
        let account_recovery_configured = context.account_recovery_configured;
        let _realm_tree_nodes = context.realm_tree_nodes;
        let _new_space_context_node = context.new_space_context_node;
        let state_store = context.state_store.clone();
        let base_url = context.base_url.get_untracked();
        let plaintext_service_id = context
            .server_description
            .get_untracked()
            .as_ref()
            .map(|description| description.service_id.as_str().to_owned())
            .unwrap_or_default();
        let create_step = self.create_step;
        let realm_title = self.realm_title;
        let realm_summary = self.realm_summary;
        let realm_alias = self.realm_alias;
        let realm_discoverability = self.realm_discoverability;
        let realm_policy_join_rule = self.realm_policy_join_rule;
        let realm_policy_history_access = self.realm_policy_history_access;
        let realm_mls_activation = self.realm_mls_activation;
        let realm_security_class = self.realm_security_class;
        let realm_federation_policy = self.realm_federation_policy;
        let realm_digest_algorithm = self.realm_digest_algorithm;
        let realm_state = self.realm_state;
        let realm_create_busy = self.realm_create_busy;
        let created_realm_id = self.created_realm_id;
        let pending_recovery_gate = self.pending_recovery_gate;
        let _new_space_realm_id = self.new_space_realm_id;
        let _new_space_title = self.new_space_title;
        let _new_space_summary = self.new_space_summary;
        let _new_space_kind = self.new_space_kind;
        let _new_space_parent_id = self.new_space_parent_id;
        let _new_space_context_seen = self.new_space_context_seen;
        let _new_space_state = self.new_space_state;
        let _new_space_created_id = self.new_space_created_id;
        let progress_strings = BootstrapProgressStrings::resolve();
        let submit = {
            let base = base_url.clone();
            let strings = progress_strings.clone();
            move |_| {
                let strings = strings.clone();
                let history_access = realm_policy_history_access.get();
                let request_mls_genesis = mls_activation_requested(&realm_mls_activation.get());
                if let Some(hint) =
                    mls_activation_history_hint(request_mls_genesis, &history_access)
                {
                    realm_state.revise(|value| {
                        *value = tr(hint);
                    });
                    return;
                }
                // `recovery_material_pending` is a normative hard gate:
                // explicit MLS initialization requires a recovery path.
                if request_mls_genesis {
                    let recovery_gate_state = active_account.get().map_or(
                        EncryptedRealmRecoveryGateState::Checking,
                        |_account| {
                            state_store.read(|store| {
                                encrypted_realm_recovery_gate_state(
                                    account_recovery_configured.get(),
                                    crate::views::recovery::recovery_options_configured(store),
                                    crate::components::mls_recovery_backup_configured(store),
                                )
                            })
                        },
                    );
                    match recovery_gate_state {
                        EncryptedRealmRecoveryGateState::Ready => {}
                        EncryptedRealmRecoveryGateState::Missing => {
                            pending_recovery_gate.revise(|value| {
                                *value = true;
                            });
                            return;
                        }
                        EncryptedRealmRecoveryGateState::Checking => {
                            let message = tr("setup.recovery_gate.checking");
                            realm_state.revise(|value| {
                                *value = message;
                            });
                            crate::components::feedback::toast_info(
                                "setup.recovery_gate.checking",
                                vec![],
                            );
                            return;
                        }
                    }
                }
                realm_create_busy.revise(|value| {
                    *value = true;
                });
                realm_state.revise(|value| {
                    *value = tr("setup.blocker.creating");
                });
                let Some(account) = active_account.get() else {
                    realm_create_busy.revise(|value| {
                        *value = false;
                    });
                    realm_state.revise(|value| {
                        *value = tr("setup.blocker.account_context_unavailable");
                    });
                    return;
                };
                let authority = account.authority.clone();
                let account_device_id = account.device_id.clone();
                let api_token = token.get();
                let base = base.clone();
                let backup_trigger_signal = crate::components::try_needs_mls_backup_state();
                let title = realm_title.get();
                let summary = realm_summary.get();
                let alias = realm_alias.get();
                let discoverability = realm_discoverability.get();
                let join_rule = realm_policy_join_rule.get();
                let security_class = realm_security_class.get();
                let federation_policy = realm_federation_policy.get();
                let digest_algorithm = realm_digest_algorithm.get();
                let actor = active_account
                    .get()
                    .map(|account| account.principal_id().to_string())
                    .unwrap_or_default();
                let configured_plaintext_service_id = plaintext_service_id.clone();
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                                            if crate::event_signer::active_signer().is_none() {
                                                match crate::event_signer::bootstrap_default_signer("inkson") {
                                                    Ok(_) => {}
                                                    Err(error) => {
                                                        let message = BootstrapProgressStrings::fill(
                                                            &strings.signer_not_ready,
                                                            &[("error", error.to_string())],
                                                        );
                                                        realm_create_busy.revise(|value|{*value=false;});
                                                        realm_state.revise(|value|{*value=message.clone();});
                                                        crate::components::feedback::toast_error(
                                                            "feedback.realm_create_failed",
                                                            vec![],
                                                            Some(message),
                                                        );
                                                        return;
                                                    }
                                                }
                                            }
                                            match authed_api_ready(&base, api_token.clone()).await {
                                                Ok(api) => {
                                                    let mut plaintext_services = plaintext_services_for_policy(
                                                        &configured_plaintext_service_id,
                                                    );
                                                    if let Ok(description) = api.describe().await {
                                                        let service_id = description.service_id.as_str().trim();
                                                        if !service_id.is_empty()
                                                            && !plaintext_services
                                                                .iter()
                                                                .any(|existing| existing == service_id)
                                                        {
                                                            plaintext_services.push(service_id.to_owned());
                                                        }
                                                    }
                                                    // Spec realm.schema.json requires
                                                    // trust_domain on the create event.
                                                    // sync_engine caches the server's
                                                    // advertised value in
                                                    // state_store.server_trust_domain
                                                    // after describe; if it isn't set
                                                    // yet we ask the API to fall back
                                                    // to the describe response.
                                                    let cached_trust_domain = state_store.read(|store| store.load())
                                                        .server_trust_domain
                                                        .clone();
                                                    let trust_domain = match cached_trust_domain {
                                                        Some(value) if !value.trim().is_empty() => value,
                                                        _ => match api.describe().await {
                                                            Ok(desc) => desc.trust_domain.as_str().to_owned(),
                                                            Err(_) => String::new(),
                                                        },
                                                    };
                                                    let submitter = match api.event_submitter() {
                                                        Ok(submitter) => submitter,
                                                        Err(error) => {
                                                            let message = BootstrapProgressStrings::fill(
                                                                &strings.create_failed,
                                                                &[("error", error.to_string())],
                                                            );
                                                            realm_create_busy.revise(|value|{*value=false;});
                                                            realm_state.revise(|value|{*value=message.clone();});
                                                            crate::components::feedback::toast_error(
                                                                "feedback.realm_create_failed",
                                                                vec![],
                                                                Some(message),
                                                            );
                                                            return;
                                                        }
                                                    };
                                                    match crate::transport::realm_write::create_realm(
                                                        &submitter,
                                                        &actor,
                                                        &title,
                                                        Some(&summary),
                                                        &discoverability,
                                                        &join_rule,
                                                        &history_access,
                                                        &security_class,
                                                        &federation_policy,
                                                        &digest_algorithm,
                                                        &trust_domain,
                                                        plaintext_services.clone(),
                                                        (!alias.trim().is_empty()).then(|| alias.trim()),
                                                        request_mls_genesis.then_some(&account_device_id),
                                                    ).await {
                                                    Ok(realm) => {
                                                        // R15: ak.realm.create now returns
                                                        // RealmCreationView with the new
                                                        // `ak:realm:*` id under `realm_id`.
                                                        let realm_id = realm.realm_id.clone();
                                                        if realm.first_commit.realm_id.as_str() != realm_id
                                                            || realm.first_commit.stream_position != 0
                                                        {
                                                            let error = tr("setup.error.non_genesis_commit")
                                                                .replace("{commit}", realm.first_commit.commit_id.as_ref());
                                                            let message = BootstrapProgressStrings::fill(
                                                                &strings.created_then_failed,
                                                                &[("id", realm_id.clone()), ("error", error)],
                                                            );
                                                            realm_create_busy.revise(|value|{*value=false;});
                                                            realm_state.revise(|value|{*value=message.clone();});
                                                            crate::components::feedback::toast_error(
                                                                "feedback.realm_create_failed",
                                                                vec![],
                                                                Some(message),
                                                            );
                                                            return;
                                                        }
                                                        tracing::debug!(
                                                            realm_id = %realm_id,
                                                            commit_id = %realm.first_commit.commit_id,
                                                            phase = "realm_founding",
                                                            state = "committed",
                                                            "Realm setup phase completed"
                                                        );
                                                        selected_realm_id.revise(|value|{*value=realm_id.clone();});
                                                        created_realm_id.revise(|value|{*value=realm_id.clone();});
                                                        // Optimistic sidebar update goes
                                                        // through the canonical store —
                                                        // the Realm tree Signal is derived
                                                        // from `state_store.realm_tree_projections`
                                                        // by RouterView's derive effect, so
                                                        // the `save_realm_tree_projection`
                                                        // below is the single write the
                                                        // sidebar picks up.
                                                        let mut projection_members = Vec::new();
                                                        if !actor.trim().is_empty() {
                                                            projection_members.push(actor.clone());
                                                        }
                                                        let projection_admins = if actor.trim().is_empty() {
                                                            Vec::new()
                                                        } else {
                                                            vec![actor.clone()]
                                                        };
                                                        let projection_body =
                                                            crate::realm_tree::OptimisticRealmTreeProjection::realm(
                                                                crate::realm_tree::RealmProjectionInput {
                                                                    owner: actor.clone(),
                                                                    admins: projection_admins,
                                                                    members: projection_members,
                                                                    title: title.clone(),
                                                                    summary: summary.clone(),
                                                                    discoverability: discoverability.clone(),
                                                                    history_access: history_access.clone(),
                                                                    plaintext_visible_services: plaintext_services.clone(),
                                                                    collaboration_role: None,
                                                                },
                                                            )
                                                            .into_value();
                                                        state_store.write(|store| store.save_realm_tree_projection(
                                                            realm_id.clone(),
                                                            projection_body,
                                                        ));
                                                        // The first authority-signed RealmCommit is the sole
                                                        // completion boundary. Keep the committed Realm
                                                        // reachable even when later product initialization
                                                        // (default discussion / MLS artifacts) needs recovery.
                                                        create_step.revise(|value|{*value=NewRealmStep::Done;});
                                                        if let Err(err) = create_initial_default_discussion(
                                                            &api,
                                                            &realm_id,
                                                            &actor,
                                                        )
                                                        .await
                                                        {
                                                            let message = BootstrapProgressStrings::fill(
                                                                &strings.created_then_failed,
                                                                &[
                                                                    ("id", realm_id.clone()),
                                                                    ("error", err.to_string()),
                                                                ],
                                                            );
                                                            realm_create_busy.revise(|value|{*value=false;});
                                                            realm_state.revise(|value|{*value=message.clone();});
                                                            crate::components::feedback::toast_error(
                                                                "feedback.realm_create_failed",
                                                                vec![],
                                                                Some(message),
                                                            );
                                                            return;
                                                        }
                                                        // The accepted Realm remains on Done throughout
                                                        // post-create setup; keep its progress visible while
                                                        // MLS initialization and backup finish below.
                                                        realm_state.revise(|value|{*value=BootstrapProgressStrings::fill(
                                                            &strings.accepted,
                                                            &[("id", realm_id.clone())],
                                                        );});

                                                        if request_mls_genesis {
                                                            tracing::debug!(
                                                                realm_id = %realm_id,
                                                                phase = "mls_genesis",
                                                                state = "pending",
                                                                "Realm setup phase started"
                                                            );
                                                            // Acquiring the accepted Commit view, verifying + pinning the
                                                            // governance proof, creating the epoch-0 group and landing
                                                            // `ak.mls.genesis` all live in the shared creator bootstrap so
                                                            // an interrupted attempt (unmount / network / closed tab) is
                                                            // replayed by the per-Realm bootstrap effect instead of leaving
                                                            // the Realm permanently unable to perform encrypted writes.
                                                            match crate::mls::creator_bootstrap::start_creator_realm_mls_genesis(
                                                                     &api,
                                                                     &state_store.handle(),
                                                                     &realm_id,
                                                                     &authority,
                                                                     &account_device_id,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(()) => {
                                                                        tracing::debug!(
                                                                            realm_id = %realm_id,
                                                                            phase = "mls_genesis",
                                                                            state = "accepted",
                                                                            "Realm setup phase completed"
                                                                        );
                                                                    }
                                                                    Err(err) => {
                                                                        tracing::warn!(
                                                                            realm_id = %realm_id,
                                                                            phase = "mls_genesis",
                                                                            state = "failed",
                                                                            error = %err,
                                                                            "Realm setup phase failed"
                                                                        );
                                                                        let message = BootstrapProgressStrings::fill(
                                                                            &strings.mls_activation_failed,
                                                                            &[
                                                                                ("id", realm_id.clone()),
                                                                                ("error", err.to_string()),
                                                                            ],
                                                                        );
                                                                        realm_create_busy.revise(|value|{*value=false;});
                                                                        realm_state.revise(|value|{*value=message.clone();});
                                                                        crate::components::feedback::toast_error(
                                                                            "feedback.realm_create_failed",
                                                                            vec![],
                                                                            Some(message),
                                                                        );
                                                                        return;
                                                                    }
                                                                }
                                                        }

                                                        let fill = BootstrapProgressStrings::fill;
                                                        let mut steps = vec![fill(
                                                            &strings.created,
                                                            &[("id", realm_id.clone())],
                                                        )];
                                                        steps.push(fill(
                                                            &strings.canonical_policy,
                                                            &[
                                                                ("discoverability", discoverability.clone()),
                                                                ("join_rule", join_rule.clone()),
                                                                (
                                                                    "history_access",
                                                                    history_access.clone(),
                                                                ),
                                                            ],
                                                        ));
                                                        if !plaintext_services.is_empty() {
                                                            steps.push(fill(
                                                                &strings.plaintext_services,
                                                                &[(
                                                                    "count",
                                                                    plaintext_services.len().to_string(),
                                                                )],
                                                            ));
                                                        }
                                                        if request_mls_genesis {
                                                            steps.push(strings.mls_ready_local.clone());
                                                        }

                                                        let message = steps.join(" · ");
                                                        realm_create_busy.revise(|value|{*value=false;});
                                                        realm_state.revise(|value|{*value=message;});
                                                        if request_mls_genesis && let Some(signal) = backup_trigger_signal {
                                                            // Realm bootstrap creates the account MLS secret
                                                            // before the first encrypted message/card write,
                                                            // so attempt the recovery-public-key backup here
                                                            // instead of waiting for a later write hook.
                                                            crate::components::maybe_auto_backup_mls_after_encrypted_write(context.clone(),
                                                                 base.clone(),
                                                                 api_token.clone(),
                                                                 authority.clone(),
                                                                 actor.clone(),
                                                                 account_device_id.to_string(),
                                                                state_store.handle(),
                                                                signal,
                                                            )
                                                            .await;
                                                        }
                                                    }
                                                    Err(error) => {
                                                        let message = if is_auth_expired_error(&error) {
                                                            strings.session_expired.clone()
                                                        } else {
                                                            BootstrapProgressStrings::fill(
                                                                &strings.create_failed,
                                                                &[("error", error.to_string())],
                                                            )
                                                        };
                                                        realm_create_busy.revise(|value|{*value=false;});
                                                        realm_state.revise(|value|{*value=message.clone();});
                                                        crate::components::feedback::toast_error(
                                                            "feedback.realm_create_failed",
                                                            vec![],
                                                            Some(message),
                                                        );
                                                    }
                                                }
                                                }
                                                Err(error) => {
                                                    let error_text = error.to_string();
                                                    let message = if crate::api_error::is_authenticated_session_unavailable_error(&error) {
                                                        strings.session_expired.clone()
                                                    } else {
                                                        BootstrapProgressStrings::fill(
                                                            &strings.invalid_server_url,
                                                            &[("error", error_text)],
                                                        )
                                                    };
                                                    realm_create_busy.revise(|value|{*value=false;});
                                                    realm_state.revise(|value|{*value=message.clone();});
                                                    crate::components::feedback::toast_error(
                                                        "feedback.realm_create_failed",
                                                        vec![],
                                                        Some(message),
                                                    );
                                                }
                                            }
                                        });
                };
            }
        };
        submit(());
    }
}

fn realm_step_contents(step: NewRealmStep) -> impl glory::ui::Widget {
    glory::ui::group().fill((
        glory::ui::text()
            .class("setup-step-index setup-step-number")
            .content(step.number()),
        glory::ui::text()
            .class("setup-step-label setup-step-copy setup-step-title")
            .content(tr(step.label_key())),
        glory::ui::text()
            .class("setup-step-subtitle muted")
            .content(tr(step.subtitle_key())),
    ))
}
pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, draft: super::SetupDraft) -> View {
    let enabled = {
        let ctx = context.clone();
        scope.bond(move || {
            realm_create_available(
                !ctx.token.get().is_empty(),
                !draft.realm_title.get().trim().is_empty(),
                !matches!(
                    policy_combination_hint(
                        &draft.realm_discoverability.get(),
                        &draft.realm_policy_join_rule.get(),
                        &draft.realm_policy_history_access.get()
                    ),
                    Some(("error", _, _))
                ) && mls_activation_history_hint(
                    mls_activation_requested(&draft.realm_mls_activation.get()),
                    &draft.realm_policy_history_access.get(),
                )
                .is_none(),
                ctx.secure_store_bootstrap_ready.get(),
                draft.realm_create_busy.get(),
                !draft.created_realm_id.get().is_empty(),
            )
        })
    };
    {
        let ctx = context.clone();
        scope.effect(move || {
            let ready = ctx.active_account.get().is_some()
                && ctx.state_store.read(|store| {
                    encrypted_realm_recovery_gate_state(
                        ctx.account_recovery_configured.get(),
                        crate::views::recovery::recovery_options_configured(store),
                        crate::components::mls_recovery_backup_configured(store),
                    )
                }) == EncryptedRealmRecoveryGateState::Ready;
            if ready && draft.pending_recovery_gate.get_untracked() {
                draft.pending_recovery_gate.revise(|v| *v = false);
            }
        });
    }
    let stepper = {
        let ctx = context.clone();
        reactive(draft.create_step, move |scope, current| {
            Box::new(glory::ui::group().fill(vec![
                    line(
                        "event-head",
                        vec![
                            plain(ctx.translated(scope, "setup.create_steps")),
                            plain(tr_args(
                                "setup.step_progress",
                                &[
                                    ("current", current.number().to_owned()),
                                    ("total", NEW_REALM_STEPS.len().to_string()),
                                ],
                            )),
                        ],
                    ),
                    stack(
                        "setup-step-list",
                        NEW_REALM_STEPS
                            .into_iter()
                            .map(|step| {
                                let selected = step == current;
                                Box::new(
                                    sapid::button()
                                        .unstyled()
                                        .class(if selected {
                                            "primary setup-step active"
                                        } else {
                                            "secondary setup-step"
                                        })
                                        .enabled(scope.bond(move || {
                                            step != NewRealmStep::Done
                                                || !draft.created_realm_id.get().is_empty()
                                        }))
                                        .fill(realm_step_contents(step))
                                        .on_press(move || draft.create_step.revise(|v| *v = step)),
                                ) as View
                            })
                            .collect(),
                    ),
                ])) as View
        })
    };
    let editor = {
        let ctx = context.clone();
        reactive(draft.create_step, move |scope, step| {
            let edit = scope.bond(move || {
                !draft.realm_create_busy.get() && draft.created_realm_id.get().is_empty()
            });
            let mut nodes = Vec::new();
            match step {
                NewRealmStep::Basics => {
                    nodes.push(stack(
                        "workflow-form setup-form-grid",
                        vec![
                            presentation::input_field(
                                scope,
                                ctx.clone(),
                                presentation::InputField {
                                    key: "realm-title-input",
                                    label: "setup.field.realm_title",
                                    prompt: "setup.field.realm_title_placeholder",
                                    value: draft.realm_title,
                                    multiline: false,
                                    required: true,
                                    span_two: false,
                                },
                                edit,
                            ),
                            presentation::input_field(
                                scope,
                                ctx.clone(),
                                presentation::InputField {
                                    key: "realm-alias-input",
                                    label: "setup.field.realm_alias",
                                    prompt: "setup.field.realm_alias_placeholder",
                                    value: draft.realm_alias,
                                    multiline: false,
                                    required: false,
                                    span_two: false,
                                },
                                edit,
                            ),
                            presentation::input_field(
                                scope,
                                ctx.clone(),
                                presentation::InputField {
                                    key: "realm-summary-input",
                                    label: "setup.field.summary",
                                    prompt: "setup.field.realm_summary_placeholder",
                                    value: draft.realm_summary,
                                    multiline: true,
                                    required: false,
                                    span_two: true,
                                },
                                edit,
                            ),
                        ],
                    ));
                    nodes.push(line(
                        "actions setup-nav-actions",
                        vec![action(
                            scope,
                            ctx.clone(),
                            "new-realm-next-button",
                            "setup.action.next_boundary",
                            "primary",
                            scope.bond(move || !draft.realm_title.get().trim().is_empty()),
                            move || draft.create_step.revise(|v| *v = v.next()),
                        )],
                    ));
                }
                NewRealmStep::Boundary => {
                    let axes = [
                        (
                            "realm-discoverability-input",
                            "setup.axis.discoverability",
                            draft.realm_discoverability,
                            DISCOVERABILITY_OPTIONS.as_slice(),
                            None,
                        ),
                        (
                            "realm-policy-join-rule-input",
                            "setup.axis.join_rule",
                            draft.realm_policy_join_rule,
                            JOIN_RULE_OPTIONS.as_slice(),
                            None,
                        ),
                        (
                            "realm-policy-history-access-input",
                            "setup.axis.history_access",
                            draft.realm_policy_history_access,
                            HISTORY_ACCESS_OPTIONS.as_slice(),
                            None,
                        ),
                        (
                            "realm-mls-activation-input",
                            "setup.axis.mls_activation",
                            draft.realm_mls_activation,
                            MLS_ACTIVATION_OPTIONS.as_slice(),
                            Some(draft.realm_policy_history_access),
                        ),
                        (
                            "realm-security-class-input",
                            "setup.axis.security_class",
                            draft.realm_security_class,
                            SECURITY_CLASS_OPTIONS.as_slice(),
                            None,
                        ),
                    ]
                    .into_iter()
                    .map(|(key, label, value, options, dependency)| {
                        presentation::axis(
                            scope,
                            ctx.clone(),
                            presentation::Axis {
                                key,
                                label,
                                value,
                                options: options.to_vec(),
                                dependency,
                                enabled: edit,
                            },
                        )
                    })
                    .collect();
                    nodes.push(stack("setup-axis-grid", axes));
                    let advanced_context = ctx.clone();
                    let federation = draft.realm_federation_policy;
                    let security = draft.realm_security_class;
                    let digest = draft.realm_digest_algorithm;
                    nodes.push(Box::new(
                        sapid::collapsible("realm-advanced-config")
                            .unstyled()
                            .class("setup-advanced realm-advanced-config")
                            .label(ctx.translated(scope, "setup.boundary.advanced_summary"))
                            .default_open(false)
                            .content_policy(sapid::ContentPolicy::KeepMounted)
                            .content(move || {
                                let context = advanced_context.clone();
                                glory::ui::widget(move |scope| {
                                    stack(
                                        "setup-axis-grid setup-advanced-grid",
                                        vec![
                                            presentation::axis(
                                                scope,
                                                context.clone(),
                                                presentation::Axis {
                                                    key: "realm-federation-policy-input",
                                                    label: "setup.axis.federation_policy",
                                                    value: federation,
                                                    options: FEDERATION_POLICY_OPTIONS.to_vec(),
                                                    dependency: Some(security),
                                                    enabled: edit,
                                                },
                                            ),
                                            presentation::axis(
                                                scope,
                                                context.clone(),
                                                presentation::Axis {
                                                    key: "realm-hash-profile-input",
                                                    label: "setup.axis.hash_profile",
                                                    value: digest,
                                                    options: HASH_PROFILE_OPTIONS.to_vec(),
                                                    dependency: None,
                                                    enabled: edit,
                                                },
                                            ),
                                        ],
                                    )
                                    .build(scope)
                                })
                            }),
                    ) as View);
                    let warning_context = ctx.clone();
                    nodes.push(crate::presentation::widgets::reactive_distinct(
                        scope.bond(move || {
                            policy_combination_hint(
                                &draft.realm_discoverability.get(),
                                &draft.realm_policy_join_rule.get(),
                                &draft.realm_policy_history_access.get(),
                            )
                        }),
                        move |scope, hint| match hint {
                            Some((tone, title, body)) => stack(
                                if tone == "error" {
                                    "inline-error"
                                } else {
                                    "inline-warn"
                                },
                                vec![line(
                                    "body",
                                    vec![
                                        plain(warning_context.translated(scope, title)),
                                        plain(warning_context.translated(scope, body)),
                                    ],
                                )],
                            ),
                            None => empty(),
                        },
                    ));
                    nodes.push(line(
                        "actions setup-nav-actions",
                        vec![
                            action(
                                scope,
                                ctx.clone(),
                                "new-realm-back-button",
                                "setup.action.back",
                                "secondary",
                                edit,
                                move || draft.create_step.revise(|value| *value = value.previous()),
                            ),
                            action(
                                scope,
                                ctx.clone(),
                                "new-realm-next-button",
                                "setup.action.next_create",
                                "primary",
                                scope.bond(move || {
                                    !matches!(
                                        policy_combination_hint(
                                            &draft.realm_discoverability.get(),
                                            &draft.realm_policy_join_rule.get(),
                                            &draft.realm_policy_history_access.get()
                                        ),
                                        Some(("error", _, _))
                                    ) && mls_activation_history_hint(
                                        mls_activation_requested(&draft.realm_mls_activation.get()),
                                        &draft.realm_policy_history_access.get(),
                                    )
                                    .is_none()
                                }),
                                move || draft.create_step.revise(|value| *value = value.next()),
                            ),
                        ],
                    ));
                }
                NewRealmStep::Create => {
                    let ctx_create = ctx.clone();
                    let blocker_context = ctx.clone();
                    let blocker_label_context = ctx.clone();
                    nodes.push(crate::presentation::widgets::reactive_distinct(
                        scope.bond(move || {
                            if !draft.created_realm_id.get().is_empty() {
                                Some("setup.blocker.already_created")
                            } else if blocker_context.token.get().trim().is_empty() {
                                Some("setup.blocker.sign_in")
                            } else if !blocker_context.secure_store_bootstrap_ready.get() {
                                Some("setup.blocker.secure_store")
                            } else if draft.realm_create_busy.get() {
                                Some("setup.blocker.creating")
                            } else {
                                None
                            }
                        }),
                        move |scope, blocker| match blocker {
                            Some(key) => stack(
                                "inline-warn realm-create-blocker",
                                vec![paragraph(
                                    "body",
                                    blocker_label_context.translated(scope, key),
                                )],
                            ),
                            None => empty(),
                        },
                    ));
                    let status_context = ctx.clone();
                    nodes.push(crate::presentation::widgets::reactive_distinct(
                        scope.bond(move || draft.realm_state.get() != tr("setup.state.draft")),
                        move |scope, visible| {
                            if visible {
                                presentation::bootstrap_status(
                                    scope,
                                    status_context.clone(),
                                    draft.realm_state,
                                )
                            } else {
                                empty()
                            }
                        },
                    ));
                    nodes.push(line(
                        "actions setup-nav-actions",
                        vec![
                            action(
                                scope,
                                ctx.clone(),
                                "new-realm-back-button",
                                "setup.action.back",
                                "secondary",
                                edit,
                                move || draft.create_step.revise(|v| *v = v.previous()),
                            ),
                            action(
                                scope,
                                ctx.clone(),
                                "create-realm-button",
                                "setup.action.create_realm",
                                "primary",
                                enabled,
                                move || draft.create_realm(ctx_create.clone()),
                            ),
                        ],
                    ));
                }
                NewRealmStep::Done => {
                    let done_context = ctx.clone();
                    nodes.push(crate::presentation::widgets::reactive_distinct(
                        scope.bond(move || !draft.created_realm_id.get().trim().is_empty()),
                        move |scope, has_created| {
                            if !has_created {
                                return paragraph("muted realm-setup-done", done_context.translated(scope, "setup.done.empty"));
                            }
                            let context = done_context.clone();
                            let realm = draft.created_realm_id;
                            let identity = Box::new(glory::ui::view().class("mono selected-realm-id")
                                .role(glory::render::Role::Group)
                                .name(realm)
                                .fill(glory::ui::text().content(scope.bond(move || crate::views::helpers::short_protocol_id(realm.get()))))) as View;
                            let navigation_context = context.clone();
                            let navigation = crate::presentation::widgets::reactive_distinct(draft.realm_create_busy, move |scope, busy| {
                                if busy {
                                    return action(scope, navigation_context.clone(), "realm-finishing", "setup.action.finishing", "primary", false, || {});
                                }
                                let navigate = navigation_context.clone();
                                let label = navigation_context.translated(scope, "setup.action.open_realm");
                                line("actions setup-nav-actions", vec![
                                    Box::new(crate::presentation::widgets::internal_link()
                                        .class("primary open-created-realm")
                                        .name(label)
                                        .target(scope.bond(move || Route::Realm { realm_id: realm.get() }.to_string()))
                                        .fill(glory::ui::text().content(label))
                                        .on(glory::render::EventKind::Activate, move |_| navigate.navigate(Route::Realm { realm_id: realm.get_untracked() }))) as View,
                                    action(scope, navigation_context.clone(), "new-realm-start-another", "setup.new_realm", "secondary",
                                        scope.bond(move || !draft.realm_create_busy.get() && !draft.pending_recovery_gate.get()),
                                        move || {
                                            if draft.created_realm_id.get_untracked().trim().is_empty() || draft.realm_create_busy.get_untracked() || draft.pending_recovery_gate.get_untracked() { return; }
                                            draft.created_realm_id.revise(|value| value.clear());
                                            draft.realm_title.revise(|value| value.clear());
                                            draft.realm_summary.revise(|value| value.clear());
                                            draft.realm_alias.revise(|value| value.clear());
                                            draft.realm_discoverability.revise(|value| *value = "listed".into());
                                            draft.realm_policy_join_rule.revise(|value| *value = "invite".into());
                                            draft.realm_policy_history_access.revise(|value| *value = "since_join".into());
                                            draft.realm_mls_activation.revise(|value| *value = "after_create".into());
                                            draft.realm_security_class.revise(|value| *value = "standard".into());
                                            draft.realm_federation_policy.revise(|value| *value = "restricted".into());
                                            draft.realm_digest_algorithm.revise(|value| *value = "sha256".into());
                                            draft.realm_state.revise(|value| *value = tr("setup.state.draft"));
                                            draft.create_step.revise(|value| *value = NewRealmStep::Basics);
                                        }),
                                ])
                            });
                            stack("realm-setup-done", vec![
                                stack("setup-summary-list", vec![line("setup-summary-row", vec![
                                    Box::new(glory::ui::text().class("setup-summary-label").content(context.translated(scope, "setup.done.created_realm"))) as View,
                                    identity,
                                ]), presentation::bootstrap_status(scope, context.clone(), draft.realm_state)]),
                                crate::components::mls_creator_retry::creator_mls_retry(scope, context.clone(), crate::components::mls_creator_retry::CreatorMlsRetryProps {
                                    realm_id: realm.into(), circle_id: None, refresh_hint: draft.realm_state.into(), token: context.token,
                                }),
                                navigation,
                            ])
                        },
                    ));
                }
            }
            stack("setup-step-panel new-realm-editor", nodes)
        })
    };
    let ctx = context.clone();
    let gate =
        reactive(draft.pending_recovery_gate, move |scope, open| {
            if !open {
                return empty();
            }
            let nav = ctx.clone();
            confirmation(
                scope,
                ctx.clone(),
                "encrypted-realm-recovery-gate",
                ctx.translated(scope, "setup.recovery_gate.title"),
                stack(
                    "modal-body",
                    vec![
                        paragraph("muted", ctx.translated(scope, "setup.recovery_gate.body")),
                        Box::new(
                            crate::presentation::widgets::internal_link()
                                .class("primary encrypted-realm-recovery-gate-setup")
                                .target(Route::SettingsRecovery.to_string())
                                .name(ctx.translated(scope, "setup.action.setup_recovery_key"))
                                .fill(glory::ui::text().content(
                                    ctx.translated(scope, "setup.action.setup_recovery_key"),
                                ))
                                .on(glory::render::EventKind::Activate, move |_| {
                                    draft.pending_recovery_gate.revise(|v| *v = false);
                                    nav.navigate(Route::SettingsRecovery);
                                }),
                        ) as View,
                    ],
                ),
                move || draft.pending_recovery_gate.revise(|v| *v = false),
            )
        });
    stack(
        "setup-shell new-realm-shell realm-lifecycle-strand",
        vec![
            stack(
                "setup-column",
                vec![stack("event new-realm-stepper", vec![stepper, editor])],
            ),
            gate,
        ],
    )
}
#[cfg(test)]
mod tests {
    use super::{
        EncryptedRealmRecoveryGateState, encrypted_realm_recovery_gate_state,
        realm_create_available,
    };

    #[test]
    fn production_step_content_is_a_valid_multiline_button() {
        for step in super::NEW_REALM_STEPS {
            let app = glory::ui::App::memory();
            let selected = app.scope().cage(false);
            app.mount(
                sapid::button()
                    .unstyled()
                    .fill(super::realm_step_contents(step))
                    .on_press(move || selected.revise(|value| *value = true)),
            )
            .unwrap();
            app.flush().unwrap();
            let button = app.tree().roots()[0];
            app.dispatch(button, glory::render::Event::Activate)
                .unwrap();
            app.flush().unwrap();
            assert!(selected.get_untracked());
        }
    }
    #[test]
    fn realm_create_does_not_wait_for_background_grant_rotation() {
        assert!(realm_create_available(true, true, true, true, false, false));
    }

    #[test]
    fn realm_create_still_waits_for_local_prerequisites() {
        assert!(!realm_create_available(
            false, true, true, true, false, false
        ));
        assert!(!realm_create_available(
            true, false, true, true, false, false
        ));
        assert!(!realm_create_available(
            true, true, false, true, false, false
        ));
        assert!(!realm_create_available(
            true, true, true, false, false, false
        ));
        assert!(!realm_create_available(true, true, true, true, true, false));
        assert!(!realm_create_available(true, true, true, true, false, true));
    }

    #[test]
    fn encrypted_realm_accepts_server_recovery_policy_without_local_cache() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(Some(true), false, false),
            EncryptedRealmRecoveryGateState::Ready
        );
    }

    #[test]
    fn encrypted_realm_waits_while_server_state_is_unknown() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, false, false),
            EncryptedRealmRecoveryGateState::Checking
        );
    }

    #[test]
    fn encrypted_realm_prompts_only_after_server_confirms_recovery_is_missing() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(Some(false), false, false),
            EncryptedRealmRecoveryGateState::Missing
        );
    }

    #[test]
    fn encrypted_realm_keeps_local_recovery_fallbacks() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, true, false),
            EncryptedRealmRecoveryGateState::Ready
        );
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, false, true),
            EncryptedRealmRecoveryGateState::Ready
        );
    }
}
