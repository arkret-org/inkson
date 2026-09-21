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

/// Whether the wizard should explicitly start MLS after Realm creation.
/// This is local workflow intent, never a Realm profile or activation proof.
pub(super) fn mls_activation_requested(selection: &str) -> bool {
    selection == "after_create"
}

/// The governing Station can accept the first MLS Genesis only while the
/// current Realm history policy is `since_join`.
pub(super) fn mls_activation_history_hint(
    activation_requested: bool,
    history_access: &str,
) -> Option<&'static str> {
    (activation_requested && history_access != "since_join")
        .then_some("setup.mls_activation.requires_since_join")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_local_choice_requests_mls_start() {
        assert!(mls_activation_requested("after_create"));
        assert!(!mls_activation_requested("not_now"));
        assert!(!mls_activation_requested("mls_rfc9420"));
        assert!(!mls_activation_requested(""));
    }

    #[test]
    fn mls_start_requires_current_since_join_without_exporter_fallback() {
        assert!(mls_activation_history_hint(true, "all_history_for_current_members").is_some());
        assert!(mls_activation_history_hint(true, "since_join").is_none());
        assert!(mls_activation_history_hint(false, "all_history_for_current_members").is_none());
    }
}
