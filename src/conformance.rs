//! Runtime conformance gates backed by the SDK's generated profile requirements.

use crate::models::{ServiceDescribe, service_supports_operation, service_supports_profile};

/// Report whether the server supports a client profile.
///
/// Until service discovery completes, the UI remains permissive. Once a
/// description is available, an explicit profile claim or complete support
/// for the SDK-generated required operation set enables the profile.
pub fn profile_ready(server: Option<&ServiceDescribe>, profile_id: &str) -> bool {
    server
        .map(|description| {
            service_supports_profile(description, profile_id)
                || missing_requirements(profile_id, description).is_empty()
        })
        .unwrap_or(true)
}

fn missing_requirements(profile_id: &str, server: &ServiceDescribe) -> Vec<String> {
    let Some(requirements) =
        arkret_wire::generated::profile_requirements::requirements_for(profile_id)
    else {
        return vec![format!("unknown profile {profile_id}")];
    };
    requirements
        .required_operations
        .iter()
        .filter(|operation| !service_supports_operation(server, operation))
        .map(|operation| (*operation).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use arkret_wire::ProfileId;

    use super::*;

    #[test]
    fn profile_ready_is_permissive_until_describe_finishes() {
        assert!(profile_ready(None, ProfileId::E2EE_CLIENT_V1));
    }
}
