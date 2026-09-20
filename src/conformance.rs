//! Feature-local runtime checks. Client conformance profiles are build claims,
//! not a list of operations every connected Station must provide.

use arkret_wire::{BindingKind, ServiceKind, ServiceOperationId, operation_bundle_descriptor};

use crate::models::ServiceDescribe;

/// Baseline operations for a view or background task. Optional actions (media,
/// encrypted authoring, recovery, etc.) keep their own operation/feature checks.
/// These are local product requirements, not new wire profiles or features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StationFeature {
    Discussion,
    Board,
    CreateRealm,
    CreateSpace,
    Circles,
    PublishKeyPackage,
    MlsAdmission,
    WelcomeBootstrap,
}

impl StationFeature {
    pub fn label_key(self) -> &'static str {
        match self {
            Self::Discussion => "route.chat",
            Self::Board => "route.board",
            Self::CreateRealm => "route.setup_realms",
            Self::CreateSpace => "route.setup_new_space",
            Self::Circles => "route.circles",
            Self::PublishKeyPackage | Self::MlsAdmission | Self::WelcomeBootstrap => {
                "route.devices"
            }
        }
    }

    /// HTTP/JSON operations actually consumed by the baseline workflow. Do not
    /// expand a client profile here or add unrelated optional-action operations.
    pub fn operations(self) -> &'static [ServiceOperationId] {
        use ServiceOperationId::*;
        match self {
            Self::Discussion => &[
                SelfCommittedEventReadScanV1,
                SelfCommittedEventResourceGetV1,
                SelfCommittedEventStreamSubscribeV1,
            ],
            Self::Board => &[
                SelfCommittedEventReadScanV1,
                SelfCommittedEventResourceGetV1,
                SelfCommittedEventStreamSubscribeV1,
                SelfSpaceReadListV1,
                SelfStrandReadListV1,
            ],
            Self::CreateRealm => &[
                ServerReadDescribeV1,
                SelfEventsCommandSubmitV1,
                SelfCommittedEventReadScanV1,
                OpenServiceReadResolutionV1,
                SelfSignerKeysReadResolveV1,
            ],
            Self::CreateSpace => &[SelfEventsCommandSubmitV1, SelfCommittedEventReadScanV1],
            Self::Circles => &[SelfCircleReadListV1],
            Self::PublishKeyPackage => &[
                SelfKeysKeypackagesUploadCreateV1,
                SelfKeysKeypackagesCommandRevokeV1,
            ],
            Self::MlsAdmission => &[
                SelfKeysKeypackagesCommandClaimV1,
                SelfKeysKeypackagesCommandConsumeV1,
                SelfEventsCommandSubmitV1,
                SelfCommittedEventReadScanV1,
            ],
            Self::WelcomeBootstrap => &[
                SelfDeviceMessagesReadListV1,
                SelfDeviceMessagesCommandAckV1,
                SelfKeysKeypackagesCommandConsumeV1,
                SelfCommittedEventReadScanV1,
            ],
        }
    }

    pub fn ready(self, server: Option<&ServiceDescribe>) -> bool {
        self.missing_requirements(server).is_empty()
    }

    /// Report exact missing operations and discovery prerequisites for diagnostics.
    pub fn missing_requirements(self, server: Option<&ServiceDescribe>) -> Vec<String> {
        let Some(server) = server else {
            return vec!["ServiceDescribe".to_owned()];
        };
        if server.service_kind != ServiceKind::Station {
            return vec!["service_kind=station".to_owned()];
        }
        if server.protocol_version.as_str() != arkret_sdk::PROTOCOL_VERSION {
            return vec!["protocol_version=1.0".to_owned()];
        }
        // The normal discovery decoder validates the description. Also fail
        // closed here for unknown/wrong-role bundles supplied by local callers.
        if server.supported_operation_bundles.iter().any(|id| {
            operation_bundle_descriptor(id)
                .is_none_or(|bundle| bundle.service_kind != server.service_kind)
        }) {
            return vec!["supported_operation_bundles".to_owned()];
        }
        self.operations()
            .iter()
            .filter(|operation| {
                server
                    .select_transport_binding(**operation, &[BindingKind::HttpJson])
                    .is_none()
            })
            .map(|operation| format!("{} (http_json)", operation.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_discovery::TransportBinding;
    use arkret_wire::{Did, ProfileId, TrustDomainId};

    use super::*;

    fn station(bundles: &[&str]) -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:web:soland.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            bundles.iter().map(|id| (*id).to_owned()).collect(),
            vec![TransportBinding::HttpJson {
                base_url: "https://soland.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn realm_creation_does_not_require_identity_resolver_or_upload_transport() {
        let description = station(&[
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core.v1",
        ]);
        assert!(!description.supports_operation(ServiceOperationId::RootIdentityReadResolveV1));
        assert!(StationFeature::CreateRealm.ready(Some(&description)));
        assert!(StationFeature::CreateSpace.ready(Some(&description)));
        assert!(StationFeature::Board.ready(Some(&description)));
    }

    #[test]
    fn missing_describe_bundle_blocks_creation_but_not_reading_or_key_publication() {
        let description = station(&["ak.operation_bundle.station.http_core.v1"]);
        assert_eq!(
            StationFeature::CreateRealm.missing_requirements(Some(&description)),
            vec!["ak.server.read.describe.v1 (http_json)"]
        );
        assert!(StationFeature::Discussion.ready(Some(&description)));
        assert!(StationFeature::PublishKeyPackage.ready(Some(&description)));
    }

    #[test]
    fn every_baseline_operation_is_a_live_registry_operation() {
        for feature in [
            StationFeature::Discussion,
            StationFeature::Board,
            StationFeature::CreateRealm,
            StationFeature::CreateSpace,
            StationFeature::Circles,
            StationFeature::PublishKeyPackage,
            StationFeature::MlsAdmission,
            StationFeature::WelcomeBootstrap,
        ] {
            for operation in feature.operations() {
                assert_eq!(
                    ServiceOperationId::from_wire(operation.as_str()),
                    Some(*operation)
                );
            }
        }
    }

    #[test]
    fn discovery_and_transport_are_required_and_profile_claims_cannot_supply_operations() {
        assert!(!StationFeature::CreateRealm.ready(None));
        let mut description = station(&[]);
        description
            .supported_profiles
            .push(ProfileId::FULL_CLIENT_V1.to_owned());
        assert!(!StationFeature::CreateRealm.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.http_core.v1"]);
        description.transport_bindings.clear();
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.http_core.v1"]);
        description.service_kind = ServiceKind::IdentityRegistry;
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.unknown.v1"]);
        assert!(!StationFeature::Discussion.ready(Some(&description)));
    }
}
