//! Pure helpers shared by the setup section components.

pub(super) fn plaintext_services_for_policy(service_id: &str) -> Vec<String> {
    let service_id = service_id.trim();
    if service_id.is_empty() {
        Vec::new()
    } else {
        vec![service_id.to_owned()]
    }
}

/// Cross-axis policy warning for the current Discoverability / Join rule /
/// History access combination.
///
/// Returns `(tone, heading_key, body_key)`. The two string fields are i18n
/// keys, not display text — this is a pure helper with unit tests, so it
/// stays out of the Dioxus runtime and the caller resolves the keys.
pub(super) fn policy_combination_hint(
    discoverability: &str,
    join_rule: &str,
    history_access: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    if discoverability == "secret" && join_rule == "public" {
        return Some((
            "error",
            "setup.policy_hint.secret_conflict",
            "setup.policy_hint.secret_conflict.body",
        ));
    }

    if discoverability == "invite_only" && join_rule == "public" {
        return Some((
            "warning",
            "setup.policy_hint.invite_public",
            "setup.policy_hint.invite_public.body",
        ));
    }

    let _ = history_access;
    None
}

pub(super) fn history_access_admits_prejoin(history_access: &str) -> bool {
    history_access.trim() == "all_history_for_current_members"
}

/// Whether the wizard's encryption selection asks for an end-to-end encrypted
/// Realm.
///
/// This is a host-side reading of this wizard's own closed option list
/// ([`super::data::ENCRYPTION_PROFILE_OPTIONS`]), not a protocol judgement. A
/// scope is plaintext until its own accepted `ak.mls.genesis` and irreversibly
/// RFC 9420 afterwards, so "is this scope encrypted" is answered by
/// [`crate::current_projection::scope_has_accepted_mls_genesis`]; at create
/// time no scope has a genesis yet, and this selection is only the intent the
/// creator is expressing.
pub(super) fn encryption_selection_is_e2ee(selection: &str) -> bool {
    !matches!(selection.trim(), "" | "none")
}

pub(super) fn normalize_content_scheme(
    encryption_is_e2ee: bool,
    history_access: &str,
    content_scheme: &str,
) -> String {
    if encryption_is_e2ee && history_access_admits_prejoin(history_access) {
        "mls_exporter_aead_v1".to_owned()
    } else {
        content_scheme.to_owned()
    }
}

/// i18n key for the content-scheme constraint violation, or `None` when the
/// current combination is valid. Key, not display text — see
/// [`policy_combination_hint`].
pub(super) fn content_scheme_constraint_hint(
    encryption_is_e2ee: bool,
    history_access: &str,
    content_scheme: &str,
) -> Option<&'static str> {
    if encryption_is_e2ee
        && history_access_admits_prejoin(history_access)
        && content_scheme.trim() == "mls_rfc9420"
    {
        Some("setup.content_scheme.prejoin_requires_exporter")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prejoin_history_access_is_detected() {
        assert!(history_access_admits_prejoin(
            "all_history_for_current_members"
        ));
        assert!(!history_access_admits_prejoin("since_join"));
    }

    #[test]
    fn e2ee_prejoin_history_normalizes_to_exporter_scheme() {
        assert_eq!(
            normalize_content_scheme(true, "all_history_for_current_members", "mls_rfc9420"),
            "mls_exporter_aead_v1"
        );
        assert_eq!(
            normalize_content_scheme(true, "since_join", "mls_rfc9420"),
            "mls_rfc9420"
        );
        assert_eq!(
            normalize_content_scheme(false, "all_history_for_current_members", "mls_rfc9420"),
            "mls_rfc9420"
        );
    }

    #[test]
    fn encryption_selection_reads_the_wizard_option_list() {
        assert!(encryption_selection_is_e2ee("mls_rfc9420"));
        assert!(!encryption_selection_is_e2ee("none"));
        assert!(!encryption_selection_is_e2ee(" "));
    }

    #[test]
    fn invalid_history_content_scheme_hint_is_specific() {
        assert!(
            content_scheme_constraint_hint(true, "all_history_for_current_members", "mls_rfc9420")
                .is_some()
        );
        assert!(
            content_scheme_constraint_hint(
                true,
                "all_history_for_current_members",
                "mls_exporter_aead_v1"
            )
            .is_none()
        );
        assert!(content_scheme_constraint_hint(true, "since_join", "mls_rfc9420").is_none());
    }
}
