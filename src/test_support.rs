//! Single authoritative source for cross-module test fixtures.
//!
//! Before this module every test file re-derived the same identifiers from the
//! same literals: roughly twenty near-identical `test_authority` / `device_id`
//! / `realm_id` helpers, several of them subtly different (one accepted only
//! the `ak:did_core:` form, one projected a `did:` first). A wire-shape change
//! therefore had twenty landing sites and no single place to fix.
//!
//! Constructors here take the widest input each identifier accepts and panic on
//! a malformed fixture, because a fixture that cannot be built is a broken test
//! rather than a runtime condition worth propagating.

/// Station used by fixtures that do not care which Station issued the account.
/// Matches the literal the per-module helpers agreed on before unification.
pub(crate) const STATION_ID: &str = "ak:did_core:web:principal.example";

/// Station used by the fixtures that model a remote server rather than the
/// local principal Station.
pub(crate) const SERVER_STATION_ID: &str = "ak:did_core:web:server.example";

/// Core id from either a stable `ak:did_core:` id or a resolvable `did:` URI.
pub(crate) fn core_id(value: &str) -> arkret_sdk::DidCoreId {
    crate::mls_api_helpers::principal_core_id(value)
        .unwrap_or_else(|error| panic!("fixture principal `{value}` is not a core id: {error}"))
}

/// Account authored at [`STATION_ID`].
pub(crate) fn authority(principal: &str) -> arkret_sdk::AccountId {
    authority_at_station(principal, STATION_ID)
}

/// Account authored at an explicit Station, for the tests whose subject is the
/// Station split itself (same principal, two servers).
pub(crate) fn authority_at_station(principal: &str, station: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(core_id(principal), core_id(station))
}

/// Account authored at the Station the operation layer currently selects, for
/// tests that must agree with `crate::operation::authoring_station_id`.
pub(crate) fn authority_at_authoring_station(principal: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(
        core_id(principal),
        crate::operation::authoring_station_id().expect("authoring station"),
    )
}

/// Complete account actor at [`STATION_ID`].
pub(crate) fn account_actor(principal: &str) -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(authority(principal))
}

pub(crate) fn device_id(value: &str) -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new(value.to_owned())
        .unwrap_or_else(|error| panic!("fixture device `{value}` is invalid: {error}"))
}

pub(crate) fn realm_id(value: &str) -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(value.to_owned())
        .unwrap_or_else(|error| panic!("fixture realm `{value}` is invalid: {error}"))
}

/// Resolvable DID for a principal given in either accepted form.
///
/// `ActiveAccountContext::new` re-projects this DID and rejects the context
/// when it disagrees with the authority, so a fixture must derive both from the
/// same input rather than pairing an arbitrary DID with an arbitrary account.
pub(crate) fn did(principal: &str) -> arkret_sdk::Did {
    let value = match principal.strip_prefix("ak:did_core:web:") {
        Some(rest) => format!("did:web:{rest}"),
        None => principal.to_owned(),
    };
    arkret_sdk::Did::new(value.clone())
        .unwrap_or_else(|error| panic!("fixture principal `{value}` is not a DID: {error}"))
}

/// Builder for a signed-in account context.
///
/// The two call sites that needed one had drifted apart in every field that is
/// not load-bearing (profile id strategy, resolution metadata, default server),
/// which made it impossible to tell which differences were deliberate. The
/// builder keeps one construction path and makes each deviation an explicit
/// call.
pub(crate) struct AccountFixture {
    principal: String,
    station: String,
    profile_id: String,
    device: String,
    server_url: String,
    method_history_head: String,
    version_id: String,
    resolution_event_ref: String,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl AccountFixture {
    pub(crate) fn new(principal: &str) -> Self {
        Self {
            principal: principal.to_owned(),
            station: STATION_ID.to_owned(),
            profile_id: "ak:profile:019b0000-0000-7000-8000-000000000001".to_owned(),
            device: "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            server_url: "https://local.host".to_owned(),
            method_history_head: "head-1".to_owned(),
            version_id: "1".to_owned(),
            resolution_event_ref: format!("ak:event:{}", "A".repeat(44)),
            updated_at: chrono::Utc::now(),
        }
    }

    pub(crate) fn station(mut self, station: &str) -> Self {
        self.station = station.to_owned();
        self
    }

    pub(crate) fn profile_id(mut self, profile_id: String) -> Self {
        self.profile_id = profile_id;
        self
    }

    pub(crate) fn device(mut self, device: &str) -> Self {
        self.device = device.to_owned();
        self
    }

    pub(crate) fn server_url(mut self, server_url: &str) -> Self {
        self.server_url = server_url.to_owned();
        self
    }

    pub(crate) fn resolution(
        mut self,
        method_history_head: &str,
        version_id: &str,
        resolution_event_ref: &str,
    ) -> Self {
        self.method_history_head = method_history_head.to_owned();
        self.version_id = version_id.to_owned();
        self.resolution_event_ref = resolution_event_ref.to_owned();
        self
    }

    pub(crate) fn updated_at(mut self, updated_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.updated_at = updated_at;
        self
    }

    pub(crate) fn authority(&self) -> arkret_sdk::AccountId {
        authority_at_station(self.principal.as_str(), self.station.as_str())
    }

    pub(crate) fn build(self) -> crate::identity::active_account::ActiveAccountContext {
        let authority = self.authority();
        crate::identity::active_account::ActiveAccountContext::new(
            self.profile_id,
            authority,
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            arkret_sdk::PrincipalResolutionProjection {
                did: did(self.principal.as_str()),
                method_history_head: self.method_history_head,
                version_id: self.version_id,
                resolution_event_ref: self.resolution_event_ref,
                updated_at: self.updated_at,
            },
            device_id(self.device.as_str()),
            url::Url::parse(self.server_url.as_str()).expect("fixture server url"),
        )
        .expect("fixture account context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_accepts_both_principal_id_forms() {
        let from_core = authority("ak:did_core:web:alice.example");
        let from_did = authority("did:web:alice.example");
        assert_eq!(from_core, from_did);
        assert_eq!(from_core.station_id.as_str(), STATION_ID);
    }

    #[test]
    fn station_split_produces_distinct_accounts() {
        let local = authority("ak:did_core:web:alice.example");
        let remote = authority_at_station("ak:did_core:web:alice.example", SERVER_STATION_ID);
        assert_ne!(local, remote);
        assert_eq!(local.principal_id, remote.principal_id);
    }
}

/// Install the Station's `ak.component.mls.epoch.v1` current value for one
/// effective scope, the only source a client may read the group's create-locked
/// `content_scheme` from once Genesis is accepted.
pub(crate) fn install_accepted_mls_epoch(
    state: &mut crate::state::LocalStateStore,
    effective_scope: &arkret_sdk::ScopeRef,
    content_scheme: &str,
) {
    let realm_id = effective_scope.realm_id_opt().unwrap().to_string();
    let group_id = effective_scope.canonical_mls_group_id().unwrap();
    let cell_id = arkret_state::mls_cells::mls_epoch_cell_id(effective_scope, &group_id).unwrap();
    let transition_ref =
        arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
    let digest = transition_ref.event_digest();
    let entry = serde_json::json!({
        "selector": {"scope_ref": effective_scope, "cell_id": cell_id},
        "target": {"kind": "realm"},
        "revision": 1,
        "result": {"status": "value", "value": {
            "transition_ref": transition_ref,
            "transition_event_digest": digest,
            "mls_transition_digest": digest,
            "effective_scope": effective_scope,
            "mls_group_id": group_id,
            "previous_epoch": 0,
            "next_epoch": 0,
            "content_scheme": content_scheme,
        }},
    });
    let mut projection = state
        .realm_tree_projection(&realm_id)
        .unwrap_or_else(|| serde_json::json!({}));
    // Add to whatever the fixture already installed: one Realm view carries the
    // Realm's own cells plus one epoch cell per MLS group it owns.
    let mut entries = projection
        .pointer("/current/entries")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    entries.retain(|existing| existing.pointer("/selector") != entry.pointer("/selector"));
    entries.push(entry);
    projection["current"]["entries"] = serde_json::Value::Array(entries);
    state.save_realm_tree_projection(&realm_id, projection);
}
