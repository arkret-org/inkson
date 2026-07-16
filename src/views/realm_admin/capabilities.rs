#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RealmMemberCapabilities {
    pub(crate) loaded: bool,
    pub(crate) can_invite: bool,
    pub(crate) can_cancel_invite: bool,
    pub(crate) can_remove: bool,
}
