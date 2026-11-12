//! Durable creator recovery status and explicit rejected-attempt retry.
use std::collections::HashMap;
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::{line, paragraph, reactive, resource};
use crate::presentation::{InksonContext, View};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RetryKey {
    generation: u64,
    holder: Option<(String, arkret_sdk::AccountId, arkret_sdk::DeviceId, String)>,
    realm: String,
    circle: Option<String>,
}

#[derive(Clone, Default)]
struct RetryFeedback {
    busy: bool,
    status: String,
    revision: u64,
}

/// Accepted commands and their feedback belong to the window, even when a
/// title, route or account frame replaces the initiating component.
pub(crate) struct CreatorRetryState {
    entries: Cage<HashMap<RetryKey, RetryFeedback>>,
}

impl CreatorRetryState {
    pub(crate) fn new(scope: &Scope) -> Self {
        Self {
            entries: scope.cage(HashMap::new()),
        }
    }

    pub(crate) fn retire_session(&self) {
        self.entries.revise(HashMap::clear);
    }

    fn read(&self, key: &RetryKey) -> RetryFeedback {
        self.entries.get().get(key).cloned().unwrap_or_default()
    }

    fn begin(&self, key: &RetryKey, status: String) -> bool {
        if self.read(key).busy {
            return false;
        }
        self.entries.revise(|entries| {
            entries.retain(|other, _| {
                other.generation == key.generation && other.holder == key.holder
            });
            let entry = entries.entry(key.clone()).or_default();
            entry.busy = true;
            entry.status = status;
        });
        true
    }

    fn finish(&self, key: &RetryKey, status: Option<String>) {
        let _ = self.entries.try_revise(|entries| {
            if let Some(entry) = entries.get_mut(key) {
                entry.busy = false;
                entry.status = status.unwrap_or_default();
                entry.revision = entry.revision.wrapping_add(1);
            }
        });
    }
}

fn retry_key(context: &InksonContext, realm: String, circle: Option<String>) -> RetryKey {
    RetryKey {
        generation: context.session_generation.get(),
        holder: context.active_account.get().map(|account| {
            (
                account.profile_id,
                account.authority,
                account.device_id,
                account.server_url.to_string(),
            )
        }),
        realm,
        circle,
    }
}

fn creator_scope(realm: String, circle: Option<String>) -> anyhow::Result<arkret_sdk::ScopeRef> {
    let realm_id = arkret_sdk::RealmId::new(realm)?;
    Ok(match circle {
        Some(circle) => arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(circle)?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id },
    })
}

pub(crate) struct CreatorMlsRetryProps {
    pub realm_id: Vary<String>,
    pub circle_id: Option<String>,
    pub refresh_hint: Vary<String>,
    pub token: Cage<String>,
}

pub(crate) fn creator_mls_retry(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: CreatorMlsRetryProps,
) -> View {
    let revision = scope.cage(0_u64);
    let _ = scope.owner().spawn(async move {
        let mut changes = crate::outbound_store::subscribe_creator_committed_changes();
        while changes.changed().await.is_ok() {
            if revision
                .try_revise(|value| *value = value.wrapping_add(1))
                .is_err()
            {
                return;
            }
        }
    });
    let realm_id = props.realm_id;
    let circle_id = props.circle_id;
    let refresh = props.refresh_hint;
    let token = props.token;
    let feedback = scope.bond({
        let context = context.clone();
        let realm = realm_id.clone();
        let circle = circle_id.clone();
        move || {
            let key = retry_key(&context, realm.get(), circle.clone());
            let state = context.creator_retry_state.read(&key);
            (key, state)
        }
    });
    let ctx = context.clone();
    let realm = realm_id.clone();
    let circle = circle_id.clone();
    let recovery = resource(scope, move || {
        let realm = realm.get();
        let circle = circle.clone();
        let _ = refresh.get();
        let _ = revision.get();
        let _ = feedback.get().1.revision;
        let _ = ctx.session_generation.get();
        let account = ctx.active_account.get();
        let base = ctx.base_url.get();
        let credential = token.get();
        async move {
            let Some(account) = account else {
                return Ok((false, false));
            };
            let Ok(scope) = creator_scope(realm, circle) else {
                return Ok((false, false));
            };
            let Ok(api) = crate::transport::auth::authed_api_ready(&base, credential).await else {
                return Ok((false, false));
            };
            let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                .with_authority(account.authority.clone());
            let record = match submitter.creator_bootstrap_record(&scope).await {
                Ok(record) => record,
                Err(_) => submitter
                    .creator_bootstrap_record(&scope)
                    .await
                    .ok()
                    .flatten(),
            };
            Ok(match record {
                Some(record) => (
                    record.rejection().is_some()
                        && record.intent().creator_device_id() == &account.device_id,
                    record.quarantine_diagnostic().is_some(),
                ),
                None => (false, false),
            })
        }
    });
    let component_owner = scope.downgrade();
    let source = scope.bond(move || (recovery.data.get(), feedback.get()));
    reactive(source, move |scope, (data, (key, current))| {
        let (retryable, quarantined) = data.and_then(|value| value.ok()).unwrap_or((false, false));
        if quarantined {
            return paragraph(
                "muted creator-mls-quarantined",
                context.translated(scope, "setup.progress.mls_quarantined"),
            );
        }
        if !retryable && !current.busy && current.status.is_empty() {
            return Box::new(widget(|_| Ok(())));
        }
        let mut children = Vec::<View>::new();
        if retryable || current.busy {
            let ctx = context.clone();
            let realm_id = realm_id.clone();
            let circle = circle_id.clone();
            let owner = component_owner.clone();
            let label = context.translated(scope, "setup.action.retry_mls");
            children.push(Box::new(
                sapid::button()
                    .unstyled()
                    .class("secondary creator-mls-retry-button")
                    .label(label)
                    .enabled(!current.busy)
                    .on_press(move || {
                        let Some(_scope) = owner.upgrade() else { return };
                        let realm = realm_id.get();
                        if retry_key(&ctx, realm.clone(), circle.clone()) != key {
                            return;
                        }
                        let Some(account) = ctx.active_account.get() else { return };
                        let generation = ctx.session_generation.get();
                        let active = ctx.active_account.get();
                        if !ctx.creator_retry_state.begin(&key, ctx.tr("setup.action.finishing")) {
                            return;
                        }
                        let base = ctx.base_url.get();
                        let credential = token.get();
                        let state_store = ctx.state_store.handle();
                        let context = ctx.clone();
                        let circle = circle.clone();
                        let key = key.clone();
                        let fence = crate::transport::auth::AuthoringSessionFence::capture();
                        let task_owner = context.clone();
                        let _ = task_owner.spawn(async move {
                            let result = async {
                                let fence = fence?;
                                fence.check()?;
                                let scope = creator_scope(realm.clone(), circle)?;
                                let api = crate::transport::auth::authed_api_ready(&base, credential).await?;
                                fence.check()?;
                                anyhow::ensure!(context.session_matches(generation, &active), "creator retry account session changed");
                                let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                                    .with_authority(account.authority.clone());
                                let record = submitter.creator_bootstrap_record(&scope).await?
                                    .ok_or_else(|| anyhow::anyhow!("creator retry lost its durable record"))?;
                                fence.check()?;
                                anyhow::ensure!(record.rejection().is_some(), "creator attempt is no longer rejected");
                                anyhow::ensure!(record.intent().creator_device_id() == &account.device_id,
                                    "creator retry requires the original device");
                                if matches!(scope, arkret_sdk::ScopeRef::Circle { .. }) {
                                    crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(
                                        &api, &state_store, &scope, &account.authority, &account.device_id, true,
                                    ).await.map_err(anyhow::Error::msg)
                                } else {
                                    crate::mls::creator_bootstrap::retry_creator_realm_mls_genesis(
                                        &api, &state_store, &realm, &account.authority, &account.device_id,
                                    ).await.map_err(anyhow::Error::msg)
                                }
                            }.await;
                            let status = context.session_matches(generation, &active).then(|| match result {
                                Ok(()) => context.tr("setup.progress.mls_ready_local"),
                                Err(error) => error.to_string(),
                            });
                            context.creator_retry_state.finish(&key, status);
                        });
                    }),
            ));
        }
        if !current.status.is_empty() {
            children.push(paragraph("muted", current.status));
        }
        line("actions creator-mls-retry", children)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn button(app: &glory::App) -> Option<(glory::render::NodeId, bool)> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            let view = node.descriptor.view();
            if view
                .classes
                .iter()
                .any(|class| class == "creator-mls-retry-button")
            {
                if let glory::render::Props::Button(button) = &view.props {
                    return Some((id, button.enabled));
                }
            }
            pending.extend(node.children.iter().copied());
        }
        None
    }

    #[test]
    fn creator_retry_feedback_survives_real_parent_replacement_and_fences_holders() {
        let _secure = crate::secure_key_store::DefaultSecureKeyStoreTestGuard::replace(
            std::sync::Arc::new(crate::secure_key_store::MemorySecureKeyStore::default()),
        );
        let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
        let account = crate::test_support::AccountFixture::new("did:web:alice.example").build();
        context
            .active_account
            .revise(|active| *active = Some(account));
        let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [71; 32],
        ))
        .to_string();
        let key = retry_key(&context, realm.clone(), None);
        assert!(
            context
                .creator_retry_state
                .begin(&key, "finishing the original attempt".into())
        );
        let repaint = app.scope().cage(0_u64);
        app.mount(reactive(repaint, {
            let context = context.clone();
            let realm = realm.clone();
            move |scope, _| {
                creator_mls_retry(
                    scope,
                    context.clone(),
                    CreatorMlsRetryProps {
                        realm_id: realm.clone().into(),
                        circle_id: None,
                        refresh_hint: String::new().into(),
                        token: context.token,
                    },
                )
            }
        }))
        .unwrap();
        app.flush().unwrap();
        let first = button(&app).expect("the original pending command has a real retry button");
        assert!(!first.1);
        context.active_account.revise(|active| {
            active.as_mut().unwrap().resolution.version_id = "fresh-resolution".into();
        });
        repaint.revise(|revision| *revision += 1);
        app.flush().unwrap();
        let second = button(&app).expect("the replacement observes the original command");
        assert_ne!(
            first.0, second.0,
            "the initiating component actually unmounted"
        );
        assert!(
            !second.1,
            "a replacement cannot enable another concurrent retry"
        );
        assert_eq!(retry_key(&context, realm.clone(), None), key);
        assert_eq!(
            context.creator_retry_state.read(&key).status,
            "finishing the original attempt"
        );
        assert!(!context.creator_retry_state.begin(&key, "duplicate".into()));
        context
            .creator_retry_state
            .finish(&key, Some("completed".into()));
        app.flush().unwrap();
        assert!(!context.creator_retry_state.read(&key).busy);
        assert_eq!(context.creator_retry_state.read(&key).revision, 1);
        context
            .session_generation
            .revise(|generation| *generation += 1);
        let next = retry_key(&context, realm.clone(), None);
        assert_ne!(next, key);
        assert!(!context.creator_retry_state.read(&next).busy);
        assert!(context.creator_retry_state.read(&next).status.is_empty());
        context.active_account.revise(|active| {
            active.as_mut().unwrap().device_id = "ak:device:01964137-0000-7000-8000-000000000002"
                .parse()
                .unwrap();
        });
        assert_ne!(retry_key(&context, realm, None), next);
    }
}
