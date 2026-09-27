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

/// Native projection inspection for the same retained store and exact actor
/// visibility selector consumed by the production chat timeline. The booleans
/// describe holder visibility; the canonical body remains in local history.
pub fn retained_blocklist_message_projection(
    store: &crate::state::LocalStateStore,
) -> Vec<(String, String, bool)> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        None,
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    messages
        .into_iter()
        .map(|message| {
            let hidden = message.actor_id.as_ref().is_some_and(|actor| {
                crate::account_data::message_actor_is_blocked(actor, &blocked)
            });
            (message.id, message.body, hidden)
        })
        .collect()
}

/// Inspect encrypted retained history through the production decrypt-on-read
/// path using the actual receiving endpoint's identity and MLS checkpoint.
pub fn retained_blocklist_message_projection_for_account(
    store: &crate::LocalStateStore,
    account: &arkret_sdk::AccountId,
    actor: &str,
    device: &arkret_sdk::DeviceId,
) -> Vec<(String, String, bool)> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        Some((account, actor, device)),
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    messages
        .into_iter()
        .map(|message| {
            let hidden = message.actor_id.as_ref().is_some_and(|actor| {
                crate::account_data::message_actor_is_blocked(actor, &blocked)
            });
            (message.id, message.body, hidden)
        })
        .collect()
}

/// Read the production automatic-receipt selector without initiating transport.
pub fn retained_blocklist_receipt_candidate(
    store: &crate::state::LocalStateStore,
    realm: &str,
    strand: &str,
) -> Option<String> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        None,
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    crate::views::chat::model::visible_read_receipt_event(&messages, realm, strand, &blocked)
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
            "ak.operation_bundle.station.http_core_current.v1",
        ]);
        assert!(!description.supports_operation(ServiceOperationId::RootIdentityReadResolveV1));
        assert!(StationFeature::CreateRealm.ready(Some(&description)));
        assert!(StationFeature::CreateSpace.ready(Some(&description)));
        assert!(StationFeature::Board.ready(Some(&description)));
    }

    #[test]
    fn missing_describe_bundle_blocks_creation_but_not_reading_or_key_publication() {
        let description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
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
        description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
        description.transport_bindings.clear();
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
        description.service_kind = ServiceKind::IdentityRegistry;
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.unknown.v1"]);
        assert!(!StationFeature::Discussion.ready(Some(&description)));
    }
}

/// Observe the Native host's actual automatic-receipt production path through
/// an instrumented transport. The ordinary Signal sender remains unchanged.
#[cfg(not(target_arch = "wasm32"))]
pub async fn send_native_automatic_read_receipt(
    host: &crate::sync_engine::NativeAccountHost,
    http: arkret_sdk::http_client::Client,
    realm: &str,
    strand: &str,
    latest_cursor: &str,
) -> anyhow::Result<Option<arkret_sdk::SignalSubmitOutcome>> {
    host.send_automatic_read_receipt_using(
        &crate::event_submit::EventSubmitter::new(http),
        realm,
        strand,
        latest_cursor,
    )
    .await
}
