//! HTTP plumbing helpers for the self-API client. Pure free functions split out
//! of `api/mod.rs` (YOU-07-001) with no logic change.

use super::*;

pub(crate) fn canonical_space_join_rule_v1(join_rule: &str) -> &str {
    match join_rule {
        "open" => "public",
        "request" => "knock",
        "invite_only" => "invite",
        value => value,
    }
}

pub(crate) fn select_join_candidate(
    resolved: &ResolveRealmOutcome,
    join_method: cokret_sdk::models::RealmJoinMethod,
) -> anyhow::Result<&RealmJoinCandidate> {
    let realm_id = trim_realm_id(resolved.realm_preview.realm_id.as_str());
    resolved
        .join_candidates
        .iter()
        .filter(|candidate| candidate.realm_id.as_str() == realm_id.as_str())
        .filter(|candidate| {
            candidate
                .operations
                .iter()
                .any(|op| op == "ck.self.events.command.submit")
        })
        .filter(|candidate| candidate.join_methods.contains(&join_method))
        .filter(|candidate| join_candidate_is_current(candidate))
        .min_by(|left, right| {
            left.priority
                .unwrap_or(u16::MAX)
                .cmp(&right.priority.unwrap_or(u16::MAX))
                .then_with(|| left.service_did.cmp(&right.service_did))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resolve_realm did not return a current join candidate for {join_method:?}"
            )
        })
}

pub(crate) fn join_candidate_is_current(candidate: &RealmJoinCandidate) -> bool {
    candidate.expires_at > chrono::Utc::now()
}

pub(crate) fn patch_touches_create_locked_encryption_profile(patch: &Value) -> bool {
    patch.as_object().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            patch_key_touches_encryption_profile(key)
                || (key == "object" && patch_value_has_direct_encryption_profile(value))
        })
    })
}

pub(crate) fn patch_key_touches_encryption_profile(key: &str) -> bool {
    key == "encryption_profile"
        || key.starts_with("encryption_profile.")
        || key == "/encryption_profile"
        || key.starts_with("/encryption_profile/")
        || key == "object.encryption_profile"
        || key.starts_with("object.encryption_profile.")
        || key == "/object/encryption_profile"
        || key.starts_with("/object/encryption_profile/")
}

pub(crate) fn patch_value_has_direct_encryption_profile(value: &Value) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|fields| fields.contains_key("encryption_profile"))
}

pub(crate) fn soland_path_allowed(normalized_path: &str) -> bool {
    let path = normalized_path
        .split(['?', '#'])
        .next()
        .unwrap_or(normalized_path);
    // Keep the marker split so this helper does not carry a direct product-path token.
    if path.starts_with(concat!("_so", "land", "/")) {
        return false;
    }
    true
}
