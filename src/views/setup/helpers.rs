//! Pure helpers shared by the setup section components.

pub(super) fn plaintext_services_for_policy(service_did: &str) -> Vec<String> {
    let service_did = service_did.trim();
    if service_did.is_empty() {
        Vec::new()
    } else {
        vec![service_did.to_owned()]
    }
}

pub(super) fn parse_seed_members(seed_members: &str) -> Vec<String> {
    let mut members = Vec::new();

    let push_unique = |value: &str, members: &mut Vec<String>| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        let normalized = crate::identity_handle::normalize_user_handle_display(trimmed)
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
