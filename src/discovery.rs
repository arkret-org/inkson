use std::collections::HashMap;

use cokret_sdk::Discoverability;
use serde::{Deserialize, Serialize};

use crate::hlc::Hlc;

pub trait DiscoverabilityExt {
    fn as_str(&self) -> &'static str;
    fn allows_discovery(&self, is_member: bool, has_invite: bool) -> bool;
}

impl DiscoverabilityExt for Discoverability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }

    /// Check if this level allows discovery by the given context.
    fn allows_discovery(&self, is_member: bool, has_invite: bool) -> bool {
        match self {
            Self::Public => true,
            Self::Listed => true,
            Self::Restricted => is_member,
            Self::Unlisted => false,
            Self::InviteOnly => has_invite,
            Self::Secret => false,
        }
    }
}

pub fn discoverability_from_str(s: &str) -> Discoverability {
    match s {
        "public" => Discoverability::Public,
        "listed" => Discoverability::Listed,
        "restricted" => Discoverability::Restricted,
        "unlisted" => Discoverability::Unlisted,
        "invite_only" => Discoverability::InviteOnly,
        "secret" => Discoverability::Secret,
        _ => Discoverability::Unlisted,
    }
}

/// Realm discovery configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmDiscovery {
    /// Realm ID.
    pub realm_id: String,
    /// Discoverability level.
    pub discoverability: Discoverability,
    /// Directory visibility settings.
    pub directory_visibility: DirectoryVisibility,
    /// Preview settings for non-members.
    pub preview: PreviewSettings,
    /// Who can discover this Realm.
    pub allowed_discoverers: Vec<String>,
    /// Anti-enumeration protection.
    pub anti_enumeration: bool,
    /// When this config was last updated.
    pub updated_at: Hlc,
}

/// Directory visibility settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryVisibility {
    /// Show in public directory.
    pub show_in_directory: bool,
    /// Show member count.
    pub show_member_count: bool,
    /// Show activity level.
    pub show_activity: bool,
    /// Custom directory tags.
    pub tags: Vec<String>,
}

/// Preview settings for non-members.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewSettings {
    /// Allow preview of recent messages.
    pub allow_message_preview: bool,
    /// Number of preview messages.
    pub preview_message_count: u32,
    /// Show member list preview.
    pub show_member_preview: bool,
    /// Number of preview members.
    pub preview_member_count: u32,
    /// Custom preview text.
    pub preview_text: Option<String>,
}

/// Organization profile status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgProfileStatus {
    /// Organization DID.
    pub org_did: String,
    /// Discoverability level.
    pub discoverability: Discoverability,
    /// Profile visibility.
    pub profile_visibility: ProfileVisibility,
    /// Directory services this org is registered with.
    pub directory_services: Vec<String>,
    /// Proofs of organization status.
    pub proofs: Vec<OrgProof>,
    /// When this profile was last updated.
    pub updated_at: Hlc,
}

/// Profile visibility settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileVisibility {
    /// Show organization name.
    pub show_name: bool,
    /// Show description.
    pub show_description: bool,
    /// Show member count.
    pub show_member_count: bool,
    /// Show domains.
    pub show_domains: bool,
    /// Show contact information.
    pub show_contact: bool,
}

/// Proof of organization status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgProof {
    /// Proof type (e.g., "dns_verification", "legal_entity").
    pub proof_type: String,
    /// Proof value.
    pub value: String,
    /// When the proof was verified.
    pub verified_at: Hlc,
    /// Who verified the proof.
    pub verified_by: String,
}

/// Display metadata for actors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisplayMetadata {
    /// Actor DID. Wire field `actor_id` per the v1 naming rule (single
    /// protocol subject uses `_id` even when the value is a DID). `alias` keeps
    /// already-stored `actor_id` payloads readable.
    #[serde(alias = "actor_id")]
    pub actor_id: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Avatar URL.
    pub avatar_url: Option<String>,
    /// Status message.
    pub status_message: Option<String>,
    /// Status emoji.
    pub status_emoji: Option<String>,
    /// Bio/description.
    pub bio: Option<String>,
    /// Location.
    pub location: Option<String>,
    /// Website URL.
    pub website: Option<String>,
    /// Custom fields.
    pub custom_fields: HashMap<String, String>,
    /// When this metadata was last updated.
    pub updated_at: Hlc,
}

impl DisplayMetadata {
    pub fn new(actor_id: &str) -> Self {
        Self {
            actor_id: actor_id.to_owned(),
            display_name: None,
            avatar_url: None,
            status_message: None,
            status_emoji: None,
            bio: None,
            location: None,
            website: None,
            custom_fields: HashMap::new(),
            updated_at: Hlc::now("yougen"),
        }
    }
}

/// Read marker for multi-device sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadMarker {
    /// Realm ID.
    pub realm_id: String,
    /// Actor DID.
    pub actor_id: String,
    /// Device ID that set this marker.
    pub device_id: String,
    /// Read scope `{kind, ref?, track_name?}`.
    pub read_scope: ReadMarkerScope,
    /// Last read position.
    pub position: ReadMarkerPosition,
    /// Read count (number of events read).
    pub read_count: u64,
    /// When this marker was set.
    pub set_at: Hlc,
}

/// Isomorphic and pending merge (05-5): fields match
/// `local_state::ReadScope`; this should later converge to a single
/// read_scope type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadMarkerScope {
    pub kind: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadMarkerPosition {
    pub event_id: String,
    pub hlc: Hlc,
}

/// Multi-device marker merge logic.
#[derive(Clone, Debug, Default)]
pub struct MarkerMerger {
    /// Markers indexed by (realm_id, actor_id, read_scope) -> device_id -> marker.
    markers: HashMap<(String, String, String), HashMap<String, ReadMarker>>,
}

impl MarkerMerger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a read marker.
    pub fn set_marker(&mut self, marker: ReadMarker) {
        let key = (
            marker.realm_id.clone(),
            marker.actor_id.clone(),
            read_marker_scope_key(&marker.read_scope),
        );
        let device_markers = self.markers.entry(key).or_default();
        device_markers.insert(marker.device_id.clone(), marker);
    }

    /// Get the merged read marker for a Realm/actor/scope.
    /// Uses the causal latest marker (highest HLC) across all devices.
    pub fn get_merged_marker(
        &self,
        realm_id: &str,
        actor_id: &str,
        read_scope: &ReadMarkerScope,
    ) -> Option<ReadMarker> {
        let key = (
            realm_id.to_owned(),
            actor_id.to_owned(),
            read_marker_scope_key(read_scope),
        );
        let device_markers = self.markers.get(&key)?;

        device_markers
            .values()
            .max_by_key(|m| &m.position.hlc)
            .cloned()
    }

    /// Get all device-specific markers for a Realm/actor/scope.
    pub fn get_device_markers(
        &self,
        realm_id: &str,
        actor_id: &str,
        read_scope: &ReadMarkerScope,
    ) -> Vec<&ReadMarker> {
        let key = (
            realm_id.to_owned(),
            actor_id.to_owned(),
            read_marker_scope_key(read_scope),
        );
        self.markers
            .get(&key)
            .map(|m| m.values().collect())
            .unwrap_or_default()
    }

    /// Get the read position for a specific device.
    pub fn get_device_marker(
        &self,
        realm_id: &str,
        actor_id: &str,
        read_scope: &ReadMarkerScope,
        device_id: &str,
    ) -> Option<&ReadMarker> {
        let key = (
            realm_id.to_owned(),
            actor_id.to_owned(),
            read_marker_scope_key(read_scope),
        );
        self.markers.get(&key)?.get(device_id)
    }
}

fn read_marker_scope_key(scope: &ReadMarkerScope) -> String {
    format!(
        "{}\n{}\n{}",
        scope.kind.as_str(),
        scope.object_ref.as_deref().unwrap_or(""),
        scope
            .track_name
            .as_deref()
            .or(scope.track_scope.as_deref())
            .unwrap_or("")
    )
}

/// Push notification E2EE metadata (minimal metadata sent to push gateway).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushE2EEMetadata {
    /// Realm ID.
    pub realm_id: String,
    /// Whether the message is encrypted.
    pub is_encrypted: bool,
    /// Message type hint (without content).
    pub message_type: String,
    /// Sender hint (minimal).
    pub sender_hint: Option<String>,
    /// Timestamp.
    pub timestamp: Hlc,
}

/// Per-result authorization filter for directory searches.
#[derive(Clone, Debug)]
pub struct AuthorizationFilter {
    /// Grants that apply to the requesting actor.
    pub grants: Vec<DirectoryGrant>,
}

impl AuthorizationFilter {
    pub fn new(grants: Vec<DirectoryGrant>) -> Self {
        Self { grants }
    }

    /// Filter search results based on authorization.
    pub fn filter_results<T>(&self, results: Vec<T>, get_realm_id: impl Fn(&T) -> &str) -> Vec<T> {
        results
            .into_iter()
            .filter(|result| {
                let realm_id = get_realm_id(result);
                self.can_access_realm(realm_id)
            })
            .collect()
    }

    /// Check if the actor can access a Realm.
    fn can_access_realm(&self, realm_id: &str) -> bool {
        // Check if any grant allows access to this Realm
        self.grants.iter().any(|grant| {
            grant
                .resource_selectors
                .iter()
                .any(|selector| selector == realm_id || selector == "*")
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGrant {
    pub resource_selectors: Vec<String>,
}

/// Discovery manager for coordinating discovery features.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryManager {
    /// Realm discovery configurations.
    realm_configs: HashMap<String, RealmDiscovery>,
    /// Organization profiles.
    org_profiles: HashMap<String, OrgProfileStatus>,
    /// Display metadata cache.
    display_metadata: HashMap<String, DisplayMetadata>,
    /// Marker merger.
    marker_merger: MarkerMerger,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set Realm discovery configuration.
    pub fn set_realm_discovery(&mut self, config: RealmDiscovery) {
        self.realm_configs.insert(config.realm_id.clone(), config);
    }

    /// Get Realm discovery configuration.
    pub fn get_realm_discovery(&self, realm_id: &str) -> Option<&RealmDiscovery> {
        self.realm_configs.get(realm_id)
    }

    /// Set organization profile.
    pub fn set_org_profile(&mut self, profile: OrgProfileStatus) {
        self.org_profiles.insert(profile.org_did.clone(), profile);
    }

    /// Get organization profile.
    pub fn get_org_profile(&self, org_did: &str) -> Option<&OrgProfileStatus> {
        self.org_profiles.get(org_did)
    }

    /// Set display metadata.
    pub fn set_display_metadata(&mut self, metadata: DisplayMetadata) {
        self.display_metadata
            .insert(metadata.actor_id.clone(), metadata);
    }

    /// Get display metadata.
    pub fn get_display_metadata(&self, actor_id: &str) -> Option<&DisplayMetadata> {
        self.display_metadata.get(actor_id)
    }

    /// Get the marker merger.
    pub fn marker_merger(&self) -> &MarkerMerger {
        &self.marker_merger
    }

    /// Get a mutable reference to the marker merger.
    pub fn marker_merger_mut(&mut self) -> &mut MarkerMerger {
        &mut self.marker_merger
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discoverability_levels() {
        assert_eq!(Discoverability::Public.as_str(), "public");
        assert_eq!(Discoverability::Secret.as_str(), "secret");
        assert_eq!(
            discoverability_from_str("invite_only"),
            Discoverability::InviteOnly
        );
    }

    #[test]
    fn test_discoverability_allows_discovery() {
        assert!(Discoverability::Public.allows_discovery(false, false));
        assert!(Discoverability::Listed.allows_discovery(false, false));
        assert!(!Discoverability::Restricted.allows_discovery(false, false));
        assert!(Discoverability::Restricted.allows_discovery(true, false));
        assert!(!Discoverability::Unlisted.allows_discovery(true, false));
        assert!(Discoverability::InviteOnly.allows_discovery(false, true));
        assert!(!Discoverability::Secret.allows_discovery(true, true));
    }

    #[test]
    fn test_display_metadata() {
        let metadata = DisplayMetadata::new("did:web:alice");
        assert_eq!(metadata.actor_id, "did:web:alice");
        assert!(metadata.display_name.is_none());
    }

    #[test]
    fn test_marker_merger_single_device() {
        let mut merger = MarkerMerger::new();
        let scope = strand_discussion_scope();

        merger.set_marker(ReadMarker {
            realm_id: "ck:realm:test".to_owned(),
            actor_id: "did:web:alice".to_owned(),
            device_id: "device-1".to_owned(),
            read_scope: scope.clone(),
            position: ReadMarkerPosition {
                event_id: "event-5".to_owned(),
                hlc: Hlc::from_parts(5000, 0, 1),
            },
            read_count: 5,
            set_at: Hlc::now("yougen"),
        });

        let merged = merger.get_merged_marker("ck:realm:test", "did:web:alice", &scope);
        assert!(merged.is_some());
        assert_eq!(merged.unwrap().position.event_id, "event-5");
    }

    #[test]
    fn test_marker_merger_multi_device() {
        let mut merger = MarkerMerger::new();
        let scope = strand_discussion_scope();

        merger.set_marker(ReadMarker {
            realm_id: "ck:realm:test".to_owned(),
            actor_id: "did:web:alice".to_owned(),
            device_id: "device-1".to_owned(),
            read_scope: scope.clone(),
            position: ReadMarkerPosition {
                event_id: "event-5".to_owned(),
                hlc: Hlc::from_parts(5000, 0, 1),
            },
            read_count: 5,
            set_at: Hlc::now("yougen"),
        });

        merger.set_marker(ReadMarker {
            realm_id: "ck:realm:test".to_owned(),
            actor_id: "did:web:alice".to_owned(),
            device_id: "device-2".to_owned(),
            read_scope: scope.clone(),
            position: ReadMarkerPosition {
                event_id: "event-8".to_owned(),
                hlc: Hlc::from_parts(8000, 0, 2),
            },
            read_count: 8,
            set_at: Hlc::now("yougen"),
        });

        let merged = merger
            .get_merged_marker("ck:realm:test", "did:web:alice", &scope)
            .unwrap();
        // Should use the device with the highest HLC (device-2)
        assert_eq!(merged.position.event_id, "event-8");
        assert_eq!(merged.device_id, "device-2");

        let devices = merger.get_device_markers("ck:realm:test", "did:web:alice", &scope);
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn test_marker_merger_per_device() {
        let mut merger = MarkerMerger::new();
        let scope = strand_discussion_scope();

        merger.set_marker(ReadMarker {
            realm_id: "ck:realm:test".to_owned(),
            actor_id: "did:web:alice".to_owned(),
            device_id: "device-1".to_owned(),
            read_scope: scope.clone(),
            position: ReadMarkerPosition {
                event_id: "event-5".to_owned(),
                hlc: Hlc::from_parts(5000, 0, 1),
            },
            read_count: 5,
            set_at: Hlc::now("yougen"),
        });

        let marker = merger.get_device_marker("ck:realm:test", "did:web:alice", &scope, "device-1");
        assert!(marker.is_some());
        assert_eq!(marker.unwrap().position.event_id, "event-5");

        assert!(
            merger
                .get_device_marker("ck:realm:test", "did:web:alice", &scope, "device-99")
                .is_none()
        );
    }

    fn strand_discussion_scope() -> ReadMarkerScope {
        ReadMarkerScope {
            kind: "strand".to_owned(),
            object_ref: Some("ck:strand:test".to_owned()),
            track_name: Some("discussion".to_owned()),
            track_scope: None,
        }
    }

    #[test]
    fn test_authorization_filter() {
        let grant = DirectoryGrant {
            resource_selectors: vec!["ck:realm:public".to_owned()],
        };

        let filter = AuthorizationFilter::new(vec![grant]);

        let results = vec![
            ("Realm A", "ck:realm:public"),
            ("Realm B", "ck:realm:private"),
        ];

        let filtered = filter.filter_results(results, |r| r.1);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, "Realm A");
    }

    #[test]
    fn test_discovery_manager() {
        let mut manager = DiscoveryManager::new();

        manager.set_realm_discovery(RealmDiscovery {
            realm_id: "ck:realm:test".to_owned(),
            discoverability: Discoverability::Public,
            directory_visibility: DirectoryVisibility {
                show_in_directory: true,
                show_member_count: true,
                show_activity: true,
                tags: vec!["test".to_owned()],
            },
            preview: PreviewSettings {
                allow_message_preview: true,
                preview_message_count: 5,
                show_member_preview: true,
                preview_member_count: 10,
                preview_text: None,
            },
            allowed_discoverers: vec![],
            anti_enumeration: false,
            updated_at: Hlc::now("yougen"),
        });

        let config = manager.get_realm_discovery("ck:realm:test");
        assert!(config.is_some());
        assert_eq!(config.unwrap().discoverability, Discoverability::Public);
    }

    #[test]
    fn test_push_e2ee_metadata() {
        let metadata = PushE2EEMetadata {
            realm_id: "ck:realm:test".to_owned(),
            is_encrypted: true,
            message_type: "message".to_owned(),
            sender_hint: Some("alice".to_owned()),
            timestamp: Hlc::now("yougen"),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("is_encrypted"));
        assert!(json.contains("ck:realm:test"));
    }
}
