//! Runtime conformance gates backed by the server's advertised operation surface.

use arkret_wire::generated::profile_requirements::ProfileOperationDirection;

use crate::models::ServiceDescribe;

/// Report whether the server exposes the operations consumed by a client profile.
///
/// Client profiles are local implementation claims and MUST NOT be copied into
/// a server's `supported_profiles`. Runtime compatibility is therefore derived
/// from the profile's recursive `consume` requirements and the exact operation
/// bundles advertised by the server. Discovery absence and unknown profiles
/// both fail closed.
pub fn profile_ready(server: Option<&ServiceDescribe>, profile_id: &str) -> bool {
    let Some(server) = server else {
        return false;
    };
    let Ok(requirements) = arkret_policy::collect_profile_semantic_requirements(&[profile_id])
    else {
        return false;
    };
    requirements
        .operation_requirements
        .iter()
        .all(|requirement| {
            requirement.direction != ProfileOperationDirection::Consume
                || server
                    .supports_operation_binding(requirement.operation_id, requirement.binding_kind)
        })
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidFullId, ProfileId, ServiceKind, TrustDomainId};

    use super::*;

    fn principal_server_description(bundles: Vec<String>) -> ServiceDescribe {
        ServiceDescribe::development(
            DidFullId::new("did:web:soland.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::PrincipalServer,
            bundles,
            Vec::new(),
        )
    }

    #[test]
    fn profile_ready_fails_closed_until_describe_finishes() {
        assert!(!profile_ready(None, ProfileId::E2EE_CLIENT_V1));
    }

    #[test]
    fn client_profile_claim_on_server_does_not_bypass_operation_negotiation() {
        let mut description = principal_server_description(Vec::new());
        description
            .supported_profiles
            .push(ProfileId::FULL_CLIENT_V1.to_owned());

        assert!(!profile_ready(
            Some(&description),
            ProfileId::FULL_CLIENT_V1
        ));
    }

    #[test]
    fn full_client_is_ready_from_principal_server_operation_bundles() {
        let description = principal_server_description(vec![
            "ak.operation_bundle.principal_server.describe.v1".to_owned(),
            "ak.operation_bundle.principal_server.http_core.v1".to_owned(),
            "ak.operation_bundle.principal_server.tus_upload.v1".to_owned(),
        ]);

        assert!(profile_ready(Some(&description), ProfileId::FULL_CLIENT_V1));
    }
}
