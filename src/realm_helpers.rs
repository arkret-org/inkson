use arkret_wire::ServiceOperationId;

use crate::models::{DirectoryRealmResolutionOutcome, RealmJoinCandidate};
use crate::operation::trim_realm_id;

pub(crate) fn validate_join_rule_v1(join_rule: &str) -> anyhow::Result<&str> {
    match join_rule {
        "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed" => {
            Ok(join_rule)
        }
        _ => Err(anyhow::anyhow!(
            "unsupported current-v1 join_rule: {join_rule}"
        )),
    }
}

pub(crate) fn select_join_candidate(
    resolved: &DirectoryRealmResolutionOutcome,
    join_method: arkret_models_discovery::RealmJoinMethod,
) -> anyhow::Result<&RealmJoinCandidate> {
    let realm_id = trim_realm_id(resolved.realm_preview.realm_id.as_str());
    resolved
        .join_candidates
        .iter()
        .filter(|candidate| candidate.validate().is_ok())
        .filter(|candidate| candidate.realm_id.as_str() == realm_id.as_str())
        .filter(|candidate| {
            candidate
                .operations
                .iter()
                .any(|op| op == ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT)
        })
        .filter(|candidate| candidate.join_methods.contains(&join_method))
        .filter(|candidate| join_candidate_is_current(candidate))
        .min_by(|left, right| {
            left.priority
                .unwrap_or(u16::MAX)
                .cmp(&right.priority.unwrap_or(u16::MAX))
                .then_with(|| left.service_id.cmp(&right.service_id))
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
