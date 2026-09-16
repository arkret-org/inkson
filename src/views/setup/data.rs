//! Static option tables for the Realm / Space create forms.
//!
//! Each entry is `(wire_value, label_key, hint_key)`. The second and third
//! fields are i18n keys, not display text — call sites resolve them through
//! [`crate::i18n::tr`] so the create forms follow the active locale like the
//! rest of the shell. The key shape is `setup.opt.<axis>.<value>[.hint]`,
//! which keeps the table mechanically checkable against the dictionaries.

pub(super) const DISCOVERABILITY_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "public",
        "setup.opt.discoverability.public",
        "setup.opt.discoverability.public.hint",
    ),
    (
        "listed",
        "setup.opt.discoverability.listed",
        "setup.opt.discoverability.listed.hint",
    ),
    (
        "restricted",
        "setup.opt.discoverability.restricted",
        "setup.opt.discoverability.restricted.hint",
    ),
    (
        "unlisted",
        "setup.opt.discoverability.unlisted",
        "setup.opt.discoverability.unlisted.hint",
    ),
    (
        "invite_only",
        "setup.opt.discoverability.invite_only",
        "setup.opt.discoverability.invite_only.hint",
    ),
    (
        "secret",
        "setup.opt.discoverability.secret",
        "setup.opt.discoverability.secret.hint",
    ),
];

pub(super) const JOIN_RULE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "public",
        "setup.opt.join_rule.public",
        "setup.opt.join_rule.public.hint",
    ),
    (
        "invite",
        "setup.opt.join_rule.invite",
        "setup.opt.join_rule.invite.hint",
    ),
    (
        "knock",
        "setup.opt.join_rule.knock",
        "setup.opt.join_rule.knock.hint",
    ),
    (
        "restricted",
        "setup.opt.join_rule.restricted",
        "setup.opt.join_rule.restricted.hint",
    ),
];

pub(super) const HISTORY_ACCESS_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "since_join",
        "setup.opt.history_access.since_join",
        "setup.opt.history_access.since_join.hint",
    ),
    (
        "all_history_for_current_members",
        "setup.opt.history_access.all_history_for_current_members",
        "setup.opt.history_access.all_history_for_current_members.hint",
    ),
];

// Spec realm-and-space.md §2.3 — `encryption_profile` enum on the
// Realm create event. `create-locked`, so this choice is permanent for
// the lifetime of the Realm.
pub(super) const ENCRYPTION_PROFILE_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "mls_rfc9420",
        "setup.opt.encryption_profile.mls_rfc9420",
        "setup.opt.encryption_profile.mls_rfc9420.hint",
    ),
    (
        "none",
        "setup.opt.encryption_profile.none",
        "setup.opt.encryption_profile.none.hint",
    ),
];

// encryption-and-audit.md §2.10 — Realm `content_scheme` (the capability axis,
// orthogonal to `history_access`, the scope-level delivery policy).
// `mls_exporter_aead_v1` makes every epoch's content structurally shareable to
// late joiners (forward secrecy degrades to per-epoch, §2.10.5);
// `mls_rfc9420` keeps per-message forward secrecy and makes pre-join history
// permanently unshareable. Default capable — matches most collaboration needs.
pub(super) const CONTENT_SCHEME_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "mls_exporter_aead_v1",
        "setup.opt.content_scheme.mls_exporter_aead_v1",
        "setup.opt.content_scheme.mls_exporter_aead_v1.hint",
    ),
    (
        "mls_rfc9420",
        "setup.opt.content_scheme.mls_rfc9420",
        "setup.opt.content_scheme.mls_rfc9420.hint",
    ),
];

// Spec realm-and-space.md §2.3 — `security_class`. `high_assurance`
// automatically locks `federation_policy` to one of
// `{closed, restricted, quarantine}`; client UI hint reflects this.
pub(super) const SECURITY_CLASS_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "standard",
        "setup.opt.security_class.standard",
        "setup.opt.security_class.standard.hint",
    ),
    (
        "high_assurance",
        "setup.opt.security_class.high_assurance",
        "setup.opt.security_class.high_assurance.hint",
    ),
];

// Spec realm-and-space.md §2.3 — `federation_policy` reducer-derived
// from `ak.realm.policy` events but seeded at create time. `open` is
// forbidden when security_class=high_assurance.
pub(super) const FEDERATION_POLICY_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "open",
        "setup.opt.federation_policy.open",
        "setup.opt.federation_policy.open.hint",
    ),
    (
        "restricted",
        "setup.opt.federation_policy.restricted",
        "setup.opt.federation_policy.restricted.hint",
    ),
    (
        "closed",
        "setup.opt.federation_policy.closed",
        "setup.opt.federation_policy.closed.hint",
    ),
    (
        "quarantine",
        "setup.opt.federation_policy.quarantine",
        "setup.opt.federation_policy.quarantine.hint",
    ),
];

// Spec realm-and-space.md §2.3 — `digest_algorithm`. Create-locked.
// `sha256` is the universal default; other choices target hardened
// or interop-with-other-hash-systems deployments.
pub(super) const HASH_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "sha256",
        "setup.opt.hash_profile.sha256",
        "setup.opt.hash_profile.sha256.hint",
    ),
    (
        "sha512",
        "setup.opt.hash_profile.sha512",
        "setup.opt.hash_profile.sha512.hint",
    ),
    (
        "sha3_256",
        "setup.opt.hash_profile.sha3_256",
        "setup.opt.hash_profile.sha3_256.hint",
    ),
    (
        "blake3",
        "setup.opt.hash_profile.blake3",
        "setup.opt.hash_profile.blake3.hint",
    ),
];

// Spec realm-and-space.md §3.2 — `kind` enum for Space. v1 catalogue
// is `space` (generic) / `project` / `folder` / `board` / `list`;
// profiles may register additional kinds.
pub(super) const SPACE_KIND_OPTIONS: [(&str, &str, &str); 5] = [
    (
        "space",
        "setup.opt.space_kind.space",
        "setup.opt.space_kind.space.hint",
    ),
    (
        "project",
        "setup.opt.space_kind.project",
        "setup.opt.space_kind.project.hint",
    ),
    (
        "folder",
        "setup.opt.space_kind.folder",
        "setup.opt.space_kind.folder.hint",
    ),
    (
        "board",
        "setup.opt.space_kind.board",
        "setup.opt.space_kind.board.hint",
    ),
    (
        "list",
        "setup.opt.space_kind.list",
        "setup.opt.space_kind.list.hint",
    ),
];

/// Resolve `(label, hint)` for the currently-selected value of an option
/// table, falling back to `unset_key` when the value matches no row.
///
/// Every axis card in the create forms needs exactly this lookup, so it
/// lives here next to the tables instead of being repeated per call site.
pub(super) fn option_hint(options: &[(&str, &str, &str)], value: &str, unset_key: &str) -> String {
    let key = options
        .iter()
        .find(|(option_value, ..)| *option_value == value)
        .map_or(unset_key, |(_, _, hint_key)| *hint_key);
    crate::i18n::tr(key)
}
