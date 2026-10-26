//! Pre-accept preview of a directed Realm invite.
//!
//! The invite card loads the preview on its own, independently of Accept: a
//! loaded, restricted or failed preview never joins the Realm, and only the
//! user's explicit Accept click starts the join. The preview comes from this
//! account's own Station, which verifies the Realm's current governance
//! Station and relays what that Station's preview policy discloses.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};

use crate::i18n::tr;
use crate::presentation::{InksonContext, View};
use crate::transport::invite_join::{InvitePreviewOutcome, invite_preview_cache_key};
use crate::views::settings::widgets::*;

/// What the invite card shows about the invited Realm before Accept.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum InvitePreviewView {
    Loading,
    Disclosed(arkret_sdk::RealmPublicPreview),
    /// Nothing is disclosed to this account; the card still offers Accept.
    Restricted,
    /// The private delivery credential has not reached this device yet, so
    /// there is no locator set to ask with.
    AwaitingDelivery,
    /// The Station or the governance Station could not answer; retryable.
    Unavailable(String),
}

#[derive(Clone, PartialEq)]
struct PreviewSessionKey {
    generation: u64,
    cache_epoch: u64,
    profile_id: String,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    control_realm: arkret_sdk::RealmId,
    account_url: url::Url,
    base_url: String,
    token: String,
}

impl PreviewSessionKey {
    fn capture(
        context: &InksonContext,
        authority: &arkret_sdk::AccountId,
    ) -> std::result::Result<Self, String> {
        let account = context
            .active_account
            .try_with_untracked(Clone::clone)
            .map_err(|_| "invite preview owner retired")?
            .ok_or("invite preview has no active account")?;
        if &account.authority != authority {
            return Err("invite preview account changed".into());
        }
        let token = context
            .token
            .try_with_untracked(Clone::clone)
            .map_err(|_| "invite preview owner retired")?;
        if token.trim().is_empty() {
            return Err("invite preview has no session".into());
        }
        Ok(Self {
            generation: context
                .session_generation
                .try_with_untracked(|generation| *generation)
                .map_err(|_| "invite preview owner retired")?,
            cache_epoch: crate::identity::device_directory::session_cache_epoch(),
            profile_id: account.profile_id,
            authority: account.authority,
            device_id: account.device_id,
            control_realm: account.principal_control_realm_id,
            account_url: account.server_url,
            base_url: context
                .base_url
                .try_with_untracked(Clone::clone)
                .map_err(|_| "invite preview owner retired")?,
            token,
        })
    }

    fn matches(&self, context: &InksonContext) -> bool {
        Self::capture(context, &self.authority).as_ref().ok() == Some(self)
    }
}

#[derive(Clone, PartialEq)]
pub(super) struct InvitePreviewUiKey {
    session: PreviewSessionKey,
    realm: arkret_sdk::RealmId,
    invite: arkret_sdk::InviteId,
    delivery: Option<crate::state::StoredInviteCredential>,
}

impl InvitePreviewUiKey {
    pub(super) fn current(
        context: &InksonContext,
        authority: &arkret_sdk::AccountId,
        realm: &str,
        invite: &str,
        delivery: Option<crate::state::StoredInviteCredential>,
    ) -> std::result::Result<Self, String> {
        Ok(Self {
            session: PreviewSessionKey::capture(context, authority)?,
            realm: arkret_sdk::RealmId::new(realm.to_owned()).map_err(|error| error.to_string())?,
            invite: arkret_sdk::InviteId::new(invite.to_owned())
                .map_err(|error| error.to_string())?,
            delivery,
        })
    }
}

type PreviewResource = crate::presentation::widgets::Resource<InvitePreviewView>;

struct PreviewEntry {
    key: InvitePreviewUiKey,
    owner: glory::Scope,
    resource: PreviewResource,
}

/// UI request state belongs to the notification page, not a reconstructed row.
/// This retains failures until Retry; it does not replace the verified domain
/// preview cache or extend its nonce/assertion freshness rules.
pub(super) struct InvitePreviewResources {
    owner: glory::ui::WeakScope,
    entries: std::cell::RefCell<Vec<PreviewEntry>>,
}

impl InvitePreviewResources {
    pub(super) fn new(scope: &glory::Scope) -> Rc<Self> {
        let resources = Rc::new(Self {
            owner: scope.downgrade(),
            entries: std::cell::RefCell::new(Vec::new()),
        });
        let weak = Rc::downgrade(&resources);
        if let Err(error) = scope.on_cleanup(move || {
            if let Some(resources) = weak.upgrade() {
                resources.retain_visible(&[]);
            }
        }) {
            scope.report_error(error);
        }
        resources
    }

    /// Call after the previous feed's mounted rows have retired, before building
    /// the replacement rows. Removed targets cancel their actual request scope.
    pub(super) fn retain_visible(&self, keys: &[InvitePreviewUiKey]) {
        let previous = std::mem::take(&mut *self.entries.borrow_mut());
        let (retained, retired): (Vec<_>, Vec<_>) = previous
            .into_iter()
            .partition(|entry| keys.contains(&entry.key));
        *self.entries.borrow_mut() = retained;
        drop(retired);
    }

    fn resource(
        &self,
        key: InvitePreviewUiKey,
        create: impl FnOnce(&glory::Scope) -> PreviewResource,
    ) -> std::result::Result<PreviewResource, String> {
        let owner = self.owner.upgrade().ok_or("invite preview page retired")?;
        if let Some(entry) = self
            .entries
            .borrow()
            .iter()
            .find(|entry| entry.key == key && entry.owner.downgrade().upgrade().is_some())
        {
            return Ok(entry.resource.clone());
        }
        let child = owner.child().map_err(|error| error.to_string())?;
        let resource = create(&child);
        self.entries.borrow_mut().push(PreviewEntry {
            key,
            owner: child,
            resource: resource.clone(),
        });
        Ok(resource)
    }
}

async fn guarded_preview(
    context: Rc<InksonContext>,
    session: PreviewSessionKey,
    load: impl std::future::Future<Output = InvitePreviewView>,
) -> InvitePreviewView {
    if !session.matches(&context) {
        return InvitePreviewView::Unavailable("invite preview session changed".into());
    }
    let result = load.await;
    if session.matches(&context) {
        result
    } else {
        InvitePreviewView::Unavailable("invite preview session changed".into())
    }
}

struct CachedPreview {
    preview: arkret_sdk::RealmPublicPreview,
    cache_expires_at: DateTime<Utc>,
}

/// Disclosed answers keyed by account and exact join target, kept only while
/// the nonce-bound assertion they were verified under is unexpired.
fn preview_cache() -> &'static Mutex<HashMap<String, CachedPreview>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedPreview>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn cached_invite_preview(
    key: &str,
    now: DateTime<Utc>,
) -> Option<arkret_sdk::RealmPublicPreview> {
    let mut cache = preview_cache().lock().ok()?;
    cache.retain(|_, cached| cached.cache_expires_at > now);
    cache.get(key).map(|cached| cached.preview.clone())
}

pub(crate) fn remember_invite_preview(
    key: String,
    preview: arkret_sdk::RealmPublicPreview,
    cache_expires_at: DateTime<Utc>,
) {
    if let Ok(mut cache) = preview_cache().lock() {
        cache.insert(
            key,
            CachedPreview {
                preview,
                cache_expires_at,
            },
        );
    }
}

/// The join target this card previews, or `None` without a usable delivery
/// credential.
fn preview_target(
    realm_id: &str,
    invite_id: &str,
    credential: Option<&crate::state::StoredInviteCredential>,
) -> Option<arkret_sdk::RealmJoinTarget> {
    let credential = credential?;
    Some(arkret_sdk::RealmJoinTarget {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
        invite_id: Some(arkret_sdk::InviteId::new(invite_id.to_owned()).ok()?),
        authority_locator_hints: credential.authority_locator_hints.clone(),
    })
}

async fn load_invite_preview(
    base_url: String,
    session_credential: String,
    authority: arkret_sdk::AccountId,
    realm_id: String,
    invite_id: String,
    credential: Option<crate::state::StoredInviteCredential>,
) -> InvitePreviewView {
    let Some(target) = preview_target(&realm_id, &invite_id, credential.as_ref()) else {
        return InvitePreviewView::AwaitingDelivery;
    };
    let Ok(key) = invite_preview_cache_key(&authority, &target) else {
        return InvitePreviewView::Unavailable("invalid invite target".to_owned());
    };
    if let Some(preview) = cached_invite_preview(&key, crate::clock::now_utc()) {
        return InvitePreviewView::Disclosed(preview);
    }
    let result = crate::transport::auth::with_authed_api(&base_url, session_credential, |api| {
        let realm_id = realm_id.clone();
        let invite_id = invite_id.clone();
        async move {
            let credential =
                credential.ok_or_else(|| anyhow::anyhow!("missing invite credential"))?;
            api.preview_realm_invite(&realm_id, &invite_id, &credential)
                .await
        }
    })
    .await;
    match result {
        Ok(InvitePreviewOutcome::Disclosed {
            preview,
            cache_expires_at,
        }) => {
            remember_invite_preview(key, preview.clone(), cache_expires_at);
            InvitePreviewView::Disclosed(preview)
        }
        Ok(InvitePreviewOutcome::Restricted) => InvitePreviewView::Restricted,
        Err(error) => InvitePreviewView::Unavailable(error.display()),
    }
}

fn join_rule_label(rule: arkret_sdk::JoinRule) -> &'static str {
    match rule {
        arkret_sdk::JoinRule::Public => "notifications.invite_preview.join_rule.public",
        arkret_sdk::JoinRule::Invite => "notifications.invite_preview.join_rule.invite",
        arkret_sdk::JoinRule::Knock => "notifications.invite_preview.join_rule.knock",
        arkret_sdk::JoinRule::Restricted => "notifications.invite_preview.join_rule.restricted",
        arkret_sdk::JoinRule::KnockRestricted => {
            "notifications.invite_preview.join_rule.knock_restricted"
        }
        arkret_sdk::JoinRule::Closed => "notifications.invite_preview.join_rule.closed",
    }
}

fn history_access_label(access: arkret_sdk::HistoryAccess) -> &'static str {
    match access {
        arkret_sdk::HistoryAccess::SinceJoin => "notifications.invite_preview.history.since_join",
        arkret_sdk::HistoryAccess::AllHistoryForCurrentMembers => {
            "notifications.invite_preview.history.all_history"
        }
    }
}

pub(super) fn invite_preview(
    scope: &glory::Scope,
    context: Rc<InksonContext>,
    resources: Rc<InvitePreviewResources>,
    authority: arkret_sdk::AccountId,
    realm_id: String,
    invite_id: String,
    credential: Option<crate::state::StoredInviteCredential>,
) -> View {
    let key = InvitePreviewUiKey::current(&context, &authority, &realm_id, &invite_id, credential);
    let resource = key.and_then(|key| {
        let ctx = context.clone();
        resources.resource(key.clone(), move |owner| {
            crate::presentation::widgets::resource(owner, move || {
                // Only the resource's explicit Retry revision starts this load.
                // Unrelated projection/locale changes rebuild row presentation.
                let session = key.session.clone();
                let base = session.base_url.clone();
                let token = session.token.clone();
                let authority = session.authority.clone();
                let realm = key.realm.to_string();
                let invite = key.invite.to_string();
                let credential = key.delivery.clone();
                let context = ctx.clone();
                async move {
                    Ok(guarded_preview(context, session, async move {
                        load_invite_preview(base, token, authority, realm, invite, credential).await
                    })
                    .await)
                }
            })
        })
    });
    let resource = match resource {
        Ok(resource) => resource,
        Err(_) => {
            return stack(
                "invite-preview muted",
                vec![paragraph(
                    "invite-preview-unavailable",
                    context.translated(scope, "notifications.invite_preview.unavailable"),
                )],
            );
        }
    };
    preview_content(context, resource)
}

fn preview_content(context: Rc<InksonContext>, resource: PreviewResource) -> View {
    reactive(resource.data, {
        let ctx = context.clone();
        move |scope, result| {
            let value = match result {
                None => InvitePreviewView::Loading,
                Some(Ok(value)) => value,
                Some(Err(error)) => InvitePreviewView::Unavailable(error),
            };
            let child = match value {
                InvitePreviewView::Loading => paragraph(
                    "invite-preview-loading",
                    ctx.translated(scope, "notifications.invite_preview.loading"),
                ),
                InvitePreviewView::Restricted => paragraph(
                    "invite-preview-restricted",
                    ctx.translated(scope, "notifications.invite_preview.restricted"),
                ),
                InvitePreviewView::AwaitingDelivery => paragraph(
                    "invite-preview-awaiting",
                    ctx.translated(scope, "notifications.invite_preview.awaiting_delivery"),
                ),
                InvitePreviewView::Disclosed(preview) => {
                    let mut children = vec![];
                    if let Some(name) = preview.display_name {
                        children.push(paragraph("entity-title invite-preview-name", name));
                    }
                    children.push(paragraph(
                        "invite-preview-join-rule",
                        tr(join_rule_label(preview.join_rule)),
                    ));
                    children.push(paragraph(
                        "invite-preview-history",
                        tr(history_access_label(preview.history_access)),
                    ));
                    stack("invite-preview-disclosed", children)
                }
                InvitePreviewView::Unavailable(_reason) => stack(
                    "invite-preview-unavailable",
                    vec![
                        plain(ctx.translated(scope, "notifications.invite_preview.unavailable")),
                        action(
                            scope,
                            ctx.clone(),
                            "invite-preview-retry",
                            "notifications.invite_preview.retry",
                            "ghost",
                            true,
                            {
                                let resource = resource.clone();
                                move || resource.reload()
                            },
                        ),
                    ],
                ),
            };
            stack("invite-preview muted", vec![child])
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x31; 32],
        ))
    }

    fn invite_id(byte: u8) -> arkret_sdk::InviteId {
        arkret_sdk::InviteId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [byte; 32],
        ))
    }

    fn hint(service: &str) -> arkret_sdk::RealmJoinCandidate {
        serde_json::from_value(serde_json::json!({
            "service_kind": "station",
            "service_id": format!("ak:did_core:web:{service}.example"),
            "source": "invite"
        }))
        .unwrap()
    }

    fn credential(service: &str) -> crate::state::StoredInviteCredential {
        crate::state::StoredInviteCredential {
            realm_id: realm_id(),
            authority_locator_hints: vec![hint(service)],
            expires_at: None,
            received_at: Utc::now(),
        }
    }

    fn account(station: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
        )
    }

    fn preview() -> arkret_sdk::RealmPublicPreview {
        arkret_sdk::RealmPublicPreview {
            realm_id: realm_id(),
            join_rule: arkret_sdk::JoinRule::Invite,
            history_access: arkret_sdk::HistoryAccess::SinceJoin,
            governance_generation: 0,
            display_name: Some("Preview Realm".to_owned()),
        }
    }

    #[test]
    fn preview_needs_the_delivered_locator_set() {
        let invite = invite_id(0x41);
        assert_eq!(
            preview_target(realm_id().as_str(), invite.as_str(), None),
            None,
            "without the private delivery credential there is nothing to ask with"
        );
        let target = preview_target(
            realm_id().as_str(),
            invite.as_str(),
            Some(&credential("gov")),
        )
        .expect("target from the delivered hints");
        assert_eq!(target.invite_id.as_ref(), Some(&invite));
        assert_eq!(target.authority_locator_hints, vec![hint("gov")]);
    }

    #[test]
    fn cache_key_binds_the_exact_account_and_target() {
        let bob = account("bob-station");
        let target = |invite: u8, service: &str| {
            preview_target(
                realm_id().as_str(),
                invite_id(invite).as_str(),
                Some(&credential(service)),
            )
            .unwrap()
        };
        let key = invite_preview_cache_key(&bob, &target(0x41, "gov")).unwrap();
        assert_eq!(
            key,
            invite_preview_cache_key(&bob, &target(0x41, "gov")).unwrap()
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&account("other-station"), &target(0x41, "gov")).unwrap(),
            "the same principal at another Station is another account"
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&bob, &target(0x42, "gov")).unwrap()
        );
        assert_ne!(
            key,
            invite_preview_cache_key(&bob, &target(0x41, "elsewhere")).unwrap()
        );
    }

    #[test]
    fn cached_preview_lives_only_while_its_assertion_is_fresh() {
        let now = Utc::now();
        let key = format!("test-{}", now.timestamp_nanos_opt().unwrap_or_default());
        remember_invite_preview(key.clone(), preview(), now + chrono::Duration::seconds(30));
        assert_eq!(cached_invite_preview(&key, now), Some(preview()));
        assert_eq!(
            cached_invite_preview(&key, now + chrono::Duration::seconds(30)),
            None
        );
        assert_eq!(
            cached_invite_preview(&key, now),
            None,
            "expired entries are evicted"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod lifecycle {
        use std::cell::{Cell, RefCell};

        use super::*;

        fn harness() -> (
            glory::App,
            Rc<glory::core::executor::Executor>,
            Rc<InksonContext>,
            tempfile::TempDir,
        ) {
            let executor = Rc::new(glory::core::executor::Executor::new(64));
            let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
            let directory = tempfile::tempdir().unwrap();
            let account =
                crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
            let mut store =
                crate::state::LocalStateStore::with_path(directory.path().join("state"));
            store.switch_active_account(&account).unwrap();
            let context = InksonContext::new(
                app.scope(),
                crate::presentation::BootState {
                    config_store: crate::config::LocalConfigStore::with_path(
                        directory.path().join("config"),
                    ),
                    config: crate::config::ClientConfig::default(),
                    state_store: crate::presentation::SharedStateStore::new(store),
                    initial_credential: String::new(),
                    realm_tree_nodes: vec![],
                },
                crate::routes::Route::Notifications,
                |_| Box::pin(std::future::pending()),
            );
            context
                .active_account
                .revise(|value| *value = Some(account));
            context
                .token
                .revise(|value| *value = "preview-test-session".into());
            (app, executor, context, directory)
        }

        fn key(context: &InksonContext) -> InvitePreviewUiKey {
            InvitePreviewUiKey::current(
                context,
                &context.active_account.get_untracked().unwrap().authority,
                realm_id().as_str(),
                invite_id(0x41).as_str(),
                Some(credential("gov")),
            )
            .unwrap()
        }

        fn class_nodes(app: &glory::App, class: &str) -> Vec<glory::render::NodeId> {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut result = Vec::new();
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                if node
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|value| value == class)
                {
                    result.push(id);
                }
                pending.extend(node.children.iter().copied());
            }
            result
        }

        #[test]
        fn row_replacement_keeps_unavailable_until_the_real_retry_button_is_activated() {
            let (app, executor, context, _directory) = harness();
            let page = app.scope().child().unwrap();
            let resources = InvitePreviewResources::new(&page);
            let key = key(&context);
            let loads = Rc::new(Cell::new(0));
            let (reply, response) = tokio::sync::oneshot::channel();
            let response = Rc::new(RefCell::new(Some(response)));
            let resource = resources
                .resource(key.clone(), {
                    let loads = loads.clone();
                    move |owner| {
                        crate::presentation::widgets::resource(owner, move || {
                            loads.set(loads.get() + 1);
                            let response = response.borrow_mut().take();
                            async move {
                                Ok(match response {
                                    Some(response) => response.await.unwrap(),
                                    None => InvitePreviewView::Disclosed(preview()),
                                })
                            }
                        })
                    }
                })
                .unwrap();
            let row = page
                .mount_with(|| preview_content(context.clone(), resource.clone()))
                .unwrap();
            while executor.poll_one() {}
            app.flush().unwrap();
            reply
                .send(InvitePreviewView::Unavailable("HTTP 503".into()))
                .unwrap();
            while executor.poll_one() {}
            app.flush().unwrap();
            assert_eq!(class_nodes(&app, "invite-preview-unavailable").len(), 1);
            drop(row);
            resources.retain_visible(std::slice::from_ref(&key));
            let retained = resources
                .resource(key, |_| {
                    loads.set(loads.get() + 1);
                    resource.clone()
                })
                .unwrap();
            let _row = page
                .mount_with(|| preview_content(context.clone(), retained))
                .unwrap();
            context
                .state_revision
                .revise(|value| *value = value.wrapping_add(1));
            context
                .locale
                .revise(|value| *value = crate::i18n::UiLocale::Zh);
            while executor.poll_one() {}
            app.flush().unwrap();
            assert_eq!(
                loads.get(),
                1,
                "row/locale/projection refresh must not retry"
            );
            assert_eq!(class_nodes(&app, "invite-preview-unavailable").len(), 1);
            let retry = class_nodes(&app, "invite-preview-retry")[0];
            app.dispatch(retry, glory::render::Event::Activate).unwrap();
            app.flush().unwrap();
            while executor.poll_one() {}
            app.flush().unwrap();
            assert_eq!(loads.get(), 2);
            assert_eq!(class_nodes(&app, "invite-preview-disclosed").len(), 1);
            assert!(class_nodes(&app, "invite-preview-unavailable").is_empty());
        }

        #[test]
        fn changed_full_keys_and_page_retirement_cancel_real_pending_preview_futures() {
            for changed in [
                "session", "account", "device", "token", "realm", "invite", "delivery", "page",
            ] {
                let (app, executor, context, _directory) = harness();
                let page = app.scope().child().unwrap();
                let resources = InvitePreviewResources::new(&page);
                let key = key(&context);
                let (reply, response) = tokio::sync::oneshot::channel::<InvitePreviewView>();
                let response = Rc::new(RefCell::new(Some(response)));
                let resource = resources
                    .resource(key.clone(), move |owner| {
                        crate::presentation::widgets::resource(owner, move || {
                            let response = response.borrow_mut().take().unwrap();
                            async move { Ok(response.await.unwrap()) }
                        })
                    })
                    .unwrap();
                while executor.poll_one() {}
                app.flush().unwrap();
                if changed == "page" {
                    drop(page);
                } else {
                    let mut replacement = key;
                    match changed {
                        "session" => replacement.session.generation += 1,
                        "account" => replacement.session.authority = account("other-station"),
                        "device" => {
                            replacement.session.device_id = crate::test_support::device_id(
                                "ak:device:01964137-0000-7000-8000-000000000002",
                            )
                        }
                        "token" => replacement.session.token = "replacement-session".into(),
                        "realm" => {
                            replacement.realm = arkret_sdk::RealmId::from_event_id(
                                &arkret_sdk::EventId::from_digest(
                                    arkret_sdk::DigestSuite::Sha256,
                                    [0x32; 32],
                                ),
                            )
                        }
                        "invite" => replacement.invite = invite_id(0x42),
                        "delivery" => replacement.delivery = Some(credential("other-gov")),
                        _ => unreachable!(),
                    }
                    resources.retain_visible(&[replacement]);
                }
                assert!(
                    reply.send(InvitePreviewView::Disclosed(preview())).is_err(),
                    "{changed}"
                );
                assert!(!resource.data.is_alive(), "{changed}");
                assert!(resources.entries.borrow().is_empty());
            }
        }

        #[test]
        fn session_change_before_or_after_await_cannot_publish_disclosed_preview() {
            for before in [false, true] {
                let (app, executor, context, _directory) = harness();
                let page = app.scope().child().unwrap();
                let key = key(&context);
                let output = page.cage(None);
                let issued = Rc::new(Cell::new(false));
                let entered = issued.clone();
                let (reply, response) = tokio::sync::oneshot::channel();
                let current = context.clone();
                let _task = page
                    .spawn(async move {
                        let result = guarded_preview(current, key.session, async move {
                            entered.set(true);
                            response.await.unwrap()
                        })
                        .await;
                        output.revise(|value| *value = Some(result));
                    })
                    .unwrap();
                if !before {
                    while executor.poll_one() {}
                    assert!(issued.get());
                }
                context
                    .session_generation
                    .revise(|value| *value = value.wrapping_add(1));
                if before {
                    while executor.poll_one() {}
                    assert!(!issued.get());
                    assert!(reply.send(InvitePreviewView::Disclosed(preview())).is_err());
                } else {
                    reply.send(InvitePreviewView::Disclosed(preview())).unwrap();
                    while executor.poll_one() {}
                }
                app.flush().unwrap();
                assert!(matches!(
                    output.get_untracked(),
                    Some(InvitePreviewView::Unavailable(_))
                ));
            }
        }
    }
}
