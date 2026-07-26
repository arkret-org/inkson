//! Pure helpers shared by the setup section components.

pub(super) fn plaintext_services_for_policy(service_id: &str) -> Vec<String> {
    let service_id = service_id.trim();
    if service_id.is_empty() {
        Vec::new()
    } else {
        vec![service_id.to_owned()]
    }
}

pub(super) fn parse_seed_members(seed_members: &str) -> Vec<String> {
    let mut members = Vec::new();

    let push_unique = |value: &str, members: &mut Vec<String>| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        let normalized = crate::identity::handle::normalize_user_handle_display(trimmed)
            .unwrap_or_else(|| trimmed.to_owned());
        if !members.iter().any(|existing| existing == &normalized) {
            members.push(normalized);
        }
    };

    for candidate in seed_members.split([',', '\n', '\r', '\t', ';']) {
        push_unique(candidate, &mut members);
    }

    members
}

pub(super) fn policy_combination_hint(
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    if discoverability == "secret"
        && (join_rule == "public" || history_visibility == "world_readable")
    {
        return Some((
            "error",
            "Combination invalid",
            "A secret Space cannot also advertise public admission or world-readable history.",
        ));
    }

    if discoverability == "invite_only" && join_rule == "public" {
        return Some((
            "warning",
            "Combination is contradictory",
            "Invite-only discovery paired with public join usually means the discovery model is underspecified.",
        ));
    }

    if matches!(discoverability, "invite_only" | "secret") && history_visibility == "world_readable"
    {
        return Some((
            "warning",
            "History leaks more than existence",
            "If history is world-readable, the Space behaves more openly than its discovery setting suggests.",
        ));
    }

    None
}

pub(super) fn history_visibility_admits_prejoin(history_visibility: &str) -> bool {
    matches!(
        history_visibility.trim().to_ascii_lowercase().as_str(),
        "world_readable" | "shared" | "invited"
    )
}

pub(super) fn normalize_content_scheme(
    encryption_is_e2ee: bool,
    history_visibility: &str,
    content_scheme: &str,
) -> String {
    if encryption_is_e2ee && history_visibility_admits_prejoin(history_visibility) {
        "mls_exporter_aead_v1".to_owned()
    } else {
        content_scheme.to_owned()
    }
}

pub(super) fn content_scheme_constraint_hint(
    encryption_is_e2ee: bool,
    history_visibility: &str,
    content_scheme: &str,
) -> Option<&'static str> {
    if encryption_is_e2ee
        && history_visibility_admits_prejoin(history_visibility)
        && content_scheme.trim() == "mls_rfc9420"
    {
        Some("Pre-join history requires content_scheme=mls_exporter_aead_v1.")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prejoin_history_values_are_detected() {
        assert!(history_visibility_admits_prejoin("shared"));
        assert!(history_visibility_admits_prejoin("invited"));
        assert!(history_visibility_admits_prejoin("world_readable"));
        assert!(!history_visibility_admits_prejoin("joined"));
        assert!(!history_visibility_admits_prejoin("restricted"));
    }

    #[test]
    fn e2ee_prejoin_history_normalizes_to_exporter_scheme() {
        assert_eq!(
            normalize_content_scheme(true, "shared", "mls_rfc9420"),
            "mls_exporter_aead_v1"
        );
        assert_eq!(
            normalize_content_scheme(true, "joined", "mls_rfc9420"),
            "mls_rfc9420"
        );
        assert_eq!(
            normalize_content_scheme(false, "shared", "mls_rfc9420"),
            "mls_rfc9420"
        );
    }

    #[test]
    fn invalid_history_content_scheme_hint_is_specific() {
        assert!(content_scheme_constraint_hint(true, "shared", "mls_rfc9420").is_some());
        assert!(content_scheme_constraint_hint(true, "shared", "mls_exporter_aead_v1").is_none());
        assert!(content_scheme_constraint_hint(true, "joined", "mls_rfc9420").is_none());
    }
}
