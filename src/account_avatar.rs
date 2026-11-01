//! Canonical profile avatar state; encrypted client UI data is only a priming mirror.
use std::rc::Rc;

use glory::Cage;

#[derive(Clone, Copy)]
pub(crate) struct SettingsSessionSignals {
    pub active_account: Cage<Option<crate::config::ActiveAccountContext>>,
    pub base_url: Cage<String>,
    pub token: Cage<String>,
    pub generation: Cage<u64>,
}

// Credentials are opaque. No Debug implementation formats the session stamp.
#[derive(Clone, PartialEq)]
pub(crate) struct SettingsSessionStamp {
    account: Option<(arkret_sdk::AccountId, arkret_sdk::DeviceId, String)>,
    base_url: String,
    token: String,
    generation: u64,
}
impl SettingsSessionStamp {
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
    pub(crate) fn session_credential(&self) -> &str {
        &self.token
    }
    pub(crate) fn has_account(&self) -> bool {
        self.account.is_some()
    }
    pub(crate) fn matches_authority(&self, authority: &arkret_sdk::AccountId) -> bool {
        self.account
            .as_ref()
            .is_some_and(|(own, ..)| own == authority)
    }
}
impl SettingsSessionSignals {
    pub(crate) fn capture(self) -> SettingsSessionStamp {
        SettingsSessionStamp {
            account: self.active_account.get().map(|account| {
                (
                    account.authority,
                    account.device_id,
                    account.server_url.to_string(),
                )
            }),
            base_url: self.base_url.get(),
            token: self.token.get(),
            generation: self.generation.get(),
        }
    }
    fn try_capture_untracked(self) -> Option<SettingsSessionStamp> {
        // Each read is from the real runtime handle, without adding a reactive subscription.
        let account = self
            .active_account
            .try_with_untracked(|account| {
                account.as_ref().map(|account| {
                    (
                        account.authority.clone(),
                        account.device_id.clone(),
                        account.server_url.to_string(),
                    )
                })
            })
            .ok()?;
        let base_url = self.base_url.try_with_untracked(Clone::clone).ok()?;
        let token = self.token.try_with_untracked(Clone::clone).ok()?;
        let generation = self.generation.try_with_untracked(|value| *value).ok()?;
        Some(SettingsSessionStamp {
            account,
            base_url,
            token,
            generation,
        })
    }
    pub(crate) fn is_current(self, started: &SettingsSessionStamp) -> bool {
        self.try_capture_untracked().as_ref() == Some(started)
    }
}

/// An allocation-backed internal identity has no numeric wraparound.
/// Outstanding reads retain their allocation, so it cannot be reused as a new ticket.
#[derive(Clone)]
struct AvatarWriteRevision(Rc<()>);

impl Default for AvatarWriteRevision {
    fn default() -> Self {
        Self(Rc::new(()))
    }
}

impl PartialEq for AvatarWriteRevision {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// Unknown differs from an authoritative profile with no avatar.
/// The session stamp is intentionally not Debug: it contains a credential.
#[derive(Clone, PartialEq)]
pub(crate) struct AvatarReadTicket<S> {
    session: S,
    revision: AvatarWriteRevision,
}

#[derive(Clone, PartialEq)]
enum CanonicalAvatar {
    Unknown,
    Resolved(Option<String>),
}

#[derive(Clone, PartialEq)]
pub(crate) struct AvatarProjection<S> {
    session: Option<S>,
    canonical: CanonicalAvatar,
    write_revision: AvatarWriteRevision,
}

impl<S> Default for AvatarProjection<S> {
    fn default() -> Self {
        Self {
            session: None,
            canonical: CanonicalAvatar::Unknown,
            write_revision: AvatarWriteRevision::default(),
        }
    }
}

impl<S: Clone + PartialEq> AvatarProjection<S> {
    fn begin_read(&mut self, session: S) -> AvatarReadTicket<S> {
        if self.session.as_ref() != Some(&session) {
            self.session = Some(session.clone());
            self.canonical = CanonicalAvatar::Unknown;
            self.write_revision = AvatarWriteRevision::default();
        }
        AvatarReadTicket {
            session,
            revision: self.write_revision.clone(),
        }
    }

    fn matches(&self, ticket: &AvatarReadTicket<S>) -> bool {
        self.session.as_ref() == Some(&ticket.session) && self.write_revision == ticket.revision
    }

    fn resolve(&mut self, ticket: &AvatarReadTicket<S>, avatar: Option<String>) -> bool {
        if !self.matches(ticket) {
            return false;
        }
        self.canonical = CanonicalAvatar::Resolved(avatar);
        true
    }

    fn accepted(&mut self, session: S, avatar: Option<String>) {
        self.begin_read(session);
        self.write_revision = AvatarWriteRevision::default();
        self.canonical = CanonicalAvatar::Resolved(avatar);
    }

    fn display(&self, session: &S, mirror: Option<String>) -> String {
        if self.session.as_ref() != Some(session) {
            return String::new();
        }
        match &self.canonical {
            CanonicalAvatar::Resolved(value) => value.clone().unwrap_or_default(),
            CanonicalAvatar::Unknown => mirror.unwrap_or_default(),
        }
    }
}

// Root Scope owns the actual Glory runtime Cage; the handle itself is nonowning.
#[derive(Clone, Copy)]
pub(crate) struct AccountAvatarContext {
    pub session: SettingsSessionSignals,
    pub state: Cage<AvatarProjection<SettingsSessionStamp>>,
}
impl AccountAvatarContext {
    pub(crate) fn begin_read(self) -> Option<AvatarReadTicket<SettingsSessionStamp>> {
        let stamp = self.session.try_capture_untracked()?;
        let current = self
            .state
            .try_with_untracked(|projection| {
                (projection.session.as_ref() == Some(&stamp)).then(|| AvatarReadTicket {
                    session: stamp.clone(),
                    revision: projection.write_revision.clone(),
                })
            })
            .ok()?;
        if current.is_some() {
            return current;
        }
        self.state
            .try_revise(|projection| projection.begin_read(stamp))
            .ok()
    }
    pub(crate) fn is_current(self, ticket: &AvatarReadTicket<SettingsSessionStamp>) -> bool {
        self.session.is_current(&ticket.session)
            && self
                .state
                .try_with_untracked(|projection| projection.matches(ticket))
                .unwrap_or(false)
    }
    pub(crate) fn resolve(
        self,
        ticket: &AvatarReadTicket<SettingsSessionStamp>,
        avatar: Option<String>,
    ) -> bool {
        if !self.session.is_current(&ticket.session) {
            return false;
        }
        self.state
            .try_revise(|projection| projection.resolve(ticket, avatar))
            .unwrap_or(false)
    }
    pub(crate) fn accepted(self, stamp: &SettingsSessionStamp, avatar: Option<String>) -> bool {
        if !self.session.is_current(stamp) {
            return false;
        }
        self.state
            .try_revise(|projection| projection.accepted(stamp.clone(), avatar))
            .is_ok()
    }
    pub(crate) fn display(
        self,
        mirror: Option<String>,
        mirror_authority: Option<arkret_sdk::AccountId>,
    ) -> String {
        let stamp = self.session.capture();
        let own = stamp.account.as_ref().map(|(authority, ..)| authority);
        if stamp.token.trim().is_empty() || own.is_none() {
            return String::new();
        }
        let mirror = if own == mirror_authority.as_ref() {
            mirror
        } else {
            None
        };
        self.state
            .try_with(|projection| projection.display(&stamp, mirror))
            .unwrap_or_default()
    }
}
impl crate::presentation::InksonContext {
    pub(crate) fn account_avatar(&self) -> AccountAvatarContext {
        AccountAvatarContext {
            session: SettingsSessionSignals {
                active_account: self.active_account,
                base_url: self.base_url,
                token: self.token,
                generation: self.session_generation,
            },
            state: self.avatar_projection,
        }
    }
    pub(crate) fn account_avatar_display(&self) -> String {
        let _ = self.state_revision.get();
        let (mirror, authority) = self.state_store.read(|store| {
            (
                store.load_plain_local_data("avatar_blob_ref"),
                store.active_authority(),
            )
        });
        self.account_avatar().display(mirror, authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same coordinates as the opaque production stamp, without credentials.
    type Session = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        u64,
    );
    fn session() -> Session {
        ("actor", "device", "station", "base", "credential-a", 1)
    }

    #[test]
    fn canonical_empty_survives_late_mirror_and_failed_lookup() {
        let mut state = AvatarProjection::default();
        let ticket = state.begin_read(session());
        assert_eq!(state.display(&session(), Some("old".into())), "old");
        assert!(state.resolve(&ticket, None));
        assert_eq!(state.display(&session(), Some("old".into())), "");
        // A failed lookup does not call resolve or reset a known value.
        assert_eq!(state.display(&session(), Some("later-old".into())), "");
    }

    #[test]
    fn accepted_clear_fences_old_viewer_and_mirror_failure() {
        let mut state = AvatarProjection::default();
        let old = state.begin_read(session());
        state.accepted(session(), None);
        assert!(!state.resolve(&old, Some("old".into())));
        assert_eq!(state.display(&session(), Some("old".into())), "");
        let current = state.begin_read(session());
        assert!(state.resolve(&current, None));
        assert_eq!(state.display(&session(), Some("old".into())), "");
    }

    #[test]
    fn accepted_upload_is_shared_and_not_replaced_by_mirror() {
        let mut state = AvatarProjection::default();
        let old = state.begin_read(session());
        state.accepted(session(), Some("accepted-new".into()));
        assert_eq!(
            state.display(&session(), Some("old".into())),
            "accepted-new"
        );
        assert!(!state.resolve(&old, None));
    }

    #[test]
    fn identical_accepted_values_still_replace_read_identity() {
        let mut state = AvatarProjection::default();
        state.accepted(session(), None);
        let before = state.begin_read(session());
        state.accepted(session(), None);
        assert!(!state.resolve(&before, Some("late-avatar".into())));
        let after = state.begin_read(session());
        assert!(state.resolve(&after, None));
    }

    #[test]
    fn every_session_coordinate_fences_old_completion_and_render() {
        let base = session();
        let variants = [
            ("other", base.1, base.2, base.3, base.4, base.5),
            (base.0, "other", base.2, base.3, base.4, base.5),
            (base.0, base.1, "other", base.3, base.4, base.5),
            (base.0, base.1, base.2, "other", base.4, base.5),
            (base.0, base.1, base.2, base.3, "other", base.5),
            (base.0, base.1, base.2, base.3, base.4, 2),
        ];
        for next in variants {
            let mut state = AvatarProjection::default();
            let old = state.begin_read(base);
            state.accepted(base, Some("old-account".into()));
            assert_eq!(state.display(&next, Some("old-cache".into())), "");
            state.begin_read(next);
            assert!(!state.resolve(&old, Some("late".into())));
            assert_eq!(state.display(&next, None), "");
        }
    }

    fn scoped_avatar(owner: &glory::Owner) -> (AccountAvatarContext, arkret_sdk::AccountId) {
        let account =
            crate::test_support::AccountFixture::new("did:web:avatar-model.example").build();
        let authority = account.authority.clone();
        let context = AccountAvatarContext {
            session: SettingsSessionSignals {
                active_account: owner.cage(Some(account)),
                base_url: owner.cage("https://local.host".to_owned()),
                token: owner.cage("TEST_CREDENTIAL_PRIVATE_MARKER".to_owned()),
                generation: owner.cage(1),
            },
            state: owner.cage(AvatarProjection::default()),
        };
        (context, authority)
    }

    #[test]
    fn glory_cage_accepted_empty_and_upload_fence_late_viewer_and_mirror() {
        let runtime = glory::Runtime::new();
        let owner = runtime.owner();
        let (context, authority) = scoped_avatar(&owner);
        let old = context.begin_read().unwrap();
        assert_eq!(
            context.display(Some("old-mirror".into()), Some(authority.clone())),
            "old-mirror"
        );
        let stamp = context.session.capture();
        assert!(context.accepted(&stamp, None));
        assert!(!context.resolve(&old, Some("late-viewer".into())));
        assert_eq!(
            context.display(Some("late-mirror".into()), Some(authority.clone())),
            ""
        );
        let after_clear = context.begin_read().unwrap();
        assert!(context.accepted(&stamp, Some("accepted-upload".into())));
        assert!(!context.resolve(&after_clear, None));
        assert_eq!(
            context.display(Some("old-mirror".into()), Some(authority)),
            "accepted-upload"
        );
    }

    #[test]
    fn glory_cage_token_change_and_owner_drop_fail_closed_without_cleanup_effect() {
        let runtime = glory::Runtime::new();
        let owner = runtime.owner();
        let (context, authority) = scoped_avatar(&owner);
        let old = context.begin_read().unwrap();
        context
            .session
            .token
            .revise(|token| *token = "replacement-credential".into());
        assert!(!context.is_current(&old));
        assert!(!context.resolve(&old, Some("late".into())));
        assert_eq!(
            context.display(Some("old-mirror".into()), Some(authority)),
            ""
        );
        let next = context.begin_read().unwrap();
        drop(owner);
        assert!(!context.is_current(&next));
        assert!(context.begin_read().is_none());
    }

    #[test]
    fn glory_cage_each_live_root_fences_completion_before_a_cleanup_effect() {
        for coordinate in 0..6 {
            let runtime = glory::Runtime::new();
            let owner = runtime.owner();
            let (context, authority) = scoped_avatar(&owner);
            let stamp = context.session.capture();
            assert!(context.accepted(&stamp, Some("accepted-old".into())));
            let old = context.begin_read().unwrap();
            match coordinate {
                0 => context.session.active_account.revise(|account| {
                    *account = Some(
                        crate::test_support::AccountFixture::new("did:web:other-avatar.example")
                            .build(),
                    );
                }),
                1 => context.session.active_account.revise(|account| {
                    *account = Some(
                        crate::test_support::AccountFixture::new("did:web:avatar-model.example")
                            .device("ak:device:01964137-0000-7000-8000-000000000002")
                            .build(),
                    );
                }),
                2 => context.session.active_account.revise(|account| {
                    *account = Some(
                        crate::test_support::AccountFixture::new("did:web:avatar-model.example")
                            .server_url("https://another.station")
                            .build(),
                    );
                }),
                3 => context
                    .session
                    .base_url
                    .revise(|base| *base = "https://another.base".into()),
                4 => context
                    .session
                    .token
                    .revise(|token| *token = "replacement-credential".into()),
                _ => context
                    .session
                    .generation
                    .revise(|generation| *generation += 1),
            }
            assert!(!context.is_current(&old));
            assert!(!context.resolve(&old, Some("stale-completion".into())));
            assert!(!context.accepted(&stamp, None));
            assert_eq!(
                context.display(Some("stale-mirror".into()), Some(authority)),
                ""
            );
        }
    }
}
