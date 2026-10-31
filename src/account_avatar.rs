//! Session-fenced canonical avatar projection shared by Settings and the shell.
use std::rc::Rc;

use dioxus::prelude::*;

/// Root-owned session coordinates; each completion checks these synchronously,
/// so an account switch is effective before the UI cleanup effect is polled.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct SettingsSessionSignals {
    pub active_account: Signal<Option<crate::config::ActiveAccountContext>>,
    pub base_url: Signal<String>,
    pub token: Signal<String>,
    pub generation: Signal<u64>,
}

#[derive(Clone, PartialEq)]
pub(crate) struct SettingsSessionStamp {
    account: Option<(arkret_sdk::AccountId, arkret_sdk::DeviceId, String)>,
    base_url: String,
    token: String,
    generation: u64,
}

impl SettingsSessionStamp {
    pub(crate) fn matches_authority(&self, authority: &arkret_sdk::AccountId) -> bool {
        self.account
            .as_ref()
            .is_some_and(|(own, ..)| own == authority)
    }
}

impl SettingsSessionSignals {
    pub(crate) fn capture(self) -> SettingsSessionStamp {
        SettingsSessionStamp {
            account: (self.active_account)().map(|account| {
                (
                    account.authority,
                    account.device_id,
                    account.server_url.to_string(),
                )
            }),
            base_url: (self.base_url)(),
            token: (self.token)(),
            generation: (self.generation)(),
        }
    }

    pub(crate) fn is_current(self, started: &SettingsSessionStamp) -> bool {
        self.capture() == *started
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

/// Independent root context; the general SessionContext stays unchanged.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct AccountAvatarContext {
    pub session: SettingsSessionSignals,
    pub state: Signal<AvatarProjection<SettingsSessionStamp>>,
}

impl AccountAvatarContext {
    pub(crate) fn begin_read(self) -> AvatarReadTicket<SettingsSessionStamp> {
        let mut state = self.state;
        let stamp = self.session.capture();
        // Peek is non-subscribing; a same-session read does not notify renderers.
        let current = {
            let projection = state.peek();
            (projection.session.as_ref() == Some(&stamp)).then(|| AvatarReadTicket {
                session: stamp.clone(),
                revision: projection.write_revision.clone(),
            })
        };
        if let Some(ticket) = current {
            return ticket;
        }
        let ticket = state.write().begin_read(stamp);
        ticket
    }

    pub(crate) fn is_current(self, ticket: &AvatarReadTicket<SettingsSessionStamp>) -> bool {
        self.session.is_current(&ticket.session) && self.state.peek().matches(ticket)
    }

    pub(crate) fn resolve(
        self,
        ticket: &AvatarReadTicket<SettingsSessionStamp>,
        avatar: Option<String>,
    ) -> bool {
        if !self.session.is_current(&ticket.session) {
            return false;
        }
        let mut state = self.state;
        let accepted = state.write().resolve(ticket, avatar);
        accepted
    }

    pub(crate) fn accepted(self, stamp: &SettingsSessionStamp, avatar: Option<String>) -> bool {
        if !self.session.is_current(stamp) {
            return false;
        }
        let mut state = self.state;
        state.write().accepted(stamp.clone(), avatar);
        true
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
        self.state.read().display(&stamp, mirror)
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
}
