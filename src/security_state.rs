use std::collections::BTreeMap;

use serde_json::Value;

// YOU-05-008: shared "first non-empty string under candidate keys" helper
// lives in `crate::realm_tree`.
use crate::realm_tree::string_field;

fn bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| value.get(*key)?.as_bool())
}

fn path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

pub fn encryption_profile_is_encrypted(profile: &str) -> bool {
    let normalized = profile.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "encrypted" | "e2ee" | "mls" | "mls_rfc9420"
    )
}

fn plaintext_visibility_security_state(visibility: &str) -> Option<bool> {
    let normalized = visibility
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    match normalized.as_str() {
        "encrypted" | "e2ee" | "private_encrypted" | "mls" | "mls_rfc9420" => Some(true),
        "none" | "plain" | "plaintext" | "public_plaintext" | "server_plaintext" | "visible" => {
            Some(false)
        }
        _ => None,
    }
}

fn plaintext_visibility_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| string_field(value, &["default", "mode", "visibility"]))
}

fn decryption_state_security_state(token: &str) -> Option<bool> {
    let normalized = token.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "opaque" | "encrypted" => Some(true),
        "plaintext" => Some(false),
        _ => None,
    }
}

fn direct_security_state(value: &Value) -> Option<bool> {
    if value.get("encrypted_content").is_some()
        || value
            .get("content")
            .and_then(|content| content.get("encrypted_content"))
            .is_some()
    {
        return Some(true);
    }
    if let Some(encrypted) = bool_field(
        value,
        &[
            "__realm_security_encrypted",
            "encrypted",
            "is_encrypted",
            "e2ee",
            "end_to_end_encrypted",
        ],
    ) {
        return Some(encrypted);
    }
    if let Some(profile) = string_field(value, &["encryption_profile"]) {
        return Some(encryption_profile_is_encrypted(&profile));
    }
    if let Some(state) = string_field(value, &["decryption_state"])
        .and_then(|state| decryption_state_security_state(&state))
    {
        return Some(state);
    }
    value
        .get("plaintext_visibility")
        .and_then(plaintext_visibility_value)
        .and_then(|visibility| plaintext_visibility_security_state(&visibility))
}

pub fn strand_projection_security_state(value: &Value) -> Option<bool> {
    let paths: &[&[&str]] = &[
        &[],
        &["object"],
        &["strand"],
        &["body"],
        &["fields"],
        &["scope"],
        &["scope_circle"],
        &["metadata"],
        &["content"],
        &["tracks", "synthesis"],
    ];
    paths
        .iter()
        .filter_map(|path| path_value(value, path))
        .find_map(direct_security_state)
}

pub fn strand_projection_is_encrypted(value: &Value, inherited_realm_encrypted: bool) -> bool {
    strand_projection_security_state(value).unwrap_or(inherited_realm_encrypted)
}

pub fn projection_for_scope_id<'a>(
    projections: &'a BTreeMap<String, Value>,
    scope_id: &str,
) -> Option<&'a Value> {
    let scope_id = scope_id.trim();
    if scope_id.is_empty() {
        return None;
    }
    projections.get(scope_id)
}

fn projection_home_realm_id(body: &Value) -> Option<String> {
    body.get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
}

pub fn security_projection_for_scope_id<'a>(
    projections: &'a BTreeMap<String, Value>,
    scope_id: &str,
) -> Option<&'a Value> {
    let direct = projection_for_scope_id(projections, scope_id)?;
    projection_home_realm_id(direct)
        .and_then(|realm_id| projection_for_scope_id(projections, &realm_id))
        .or(Some(direct))
}

/// Current controller of the Realm authority-root cell, read from the locally
/// projected event log.
///
/// `ak.realm.create` is the registered genesis writer of
/// `ak.component.realm.authority_root.v1` (contract-registry.json), and its
/// registered `value_projection` sets `controller_id` from the Event
/// envelope's `actor_id`; every accepted `ak.realm.owner.transfer` afterwards
/// moves the controller to `payload.patch.controller_id`. This replays those
/// cell inputs in log order; it is not the forbidden `realm_state.owner` /
/// membership fallback — those are projection mirrors of a different fact,
/// and post-P1 realm projections no longer carry them at all.
pub fn realm_authority_root_controller_from_events(events: &[Value]) -> Option<String> {
    let mut controller: Option<String> = None;
    for event in events {
        let Some(kind) = event
            .get("kind")
            .or_else(|| event.get("event_kind"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if kind == arkret_sdk::EventKind::RealmCreate.as_str() {
            controller = event
                .get("actor_id")
                .and_then(Value::as_str)
                .map(|actor_id| actor_id.trim().to_owned())
                .filter(|actor_id| !actor_id.is_empty());
        } else if kind == arkret_wire::event_kind_str::REALM_OWNER_TRANSFER && controller.is_some()
        {
            // Only the envelope-authorized patch moves the controller; a
            // transfer projected before any create is unanchored and ignored.
            if let Some(next) = event
                .pointer("/payload/patch/controller_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|next| !next.is_empty())
            {
                controller = Some(next.to_owned());
            }
        }
    }
    controller
}

/// Fully replayed current value of the Realm authority-root cell.
///
/// Genesis comes from the accepted `ak.realm.create` (envelope `actor_id` +
/// the create-locked `capability_action_registry_digest`); the three
/// registered CAS transitions (`ak.realm.owner.transfer`,
/// `ak.realm.authority.reset`, `ak.realm.authority.basis_update`) are then
/// applied in log order, mirroring the soland reducer's
/// `apply_realm_authority_transition` effects. `None` when no create is
/// projected or the create predates the authority-root contract (no registry
/// digest) — those Realms have no root cell, matching the reducer's
/// `realm_authority_root_missing` fail-closed path.
///
/// The `canonical_sha256` of the returned value is exactly the
/// `expected_state_digest` the security-barrier governance payloads must
/// carry, so callers building `ak.realm.owner.transfer` /
/// `ak.realm.authority.{reset,basis_update}` MUST source it from here rather
/// than re-deriving fragments.
pub fn realm_authority_root_value_from_events(
    events: &[Value],
) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
    use arkret_policy::realm_bootstrap::RealmAuthorityRootValue;
    let mut root: Option<RealmAuthorityRootValue> = None;
    for event in events {
        let Some(kind) = event
            .get("kind")
            .or_else(|| event.get("event_kind"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if kind == arkret_sdk::EventKind::RealmCreate.as_str() {
            root = (|| {
                let controller = event
                    .get("actor_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|actor_id| !actor_id.is_empty())?;
                let digest = event
                    .pointer("/payload/object/capability_action_registry_digest")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|digest| !digest.is_empty())?;
                let controller_id = arkret_sdk::DidCoreId::new(controller.to_owned()).ok()?;
                let digest = arkret_sdk::Hash::new(digest.to_owned()).ok()?;
                Some(RealmAuthorityRootValue::genesis(controller_id, digest))
            })();
            continue;
        }
        let Some(current) = root.as_mut() else {
            // Transitions on a Realm with no root cell are rejected server-side
            // (`realm_authority_root_missing`); ignore them here the same way.
            continue;
        };
        match kind {
            arkret_wire::event_kind_str::REALM_OWNER_TRANSFER => {
                if let (Some(controller), Some(epoch)) = (
                    event
                        .pointer("/payload/patch/controller_id")
                        .and_then(Value::as_str)
                        .and_then(|next| arkret_sdk::DidCoreId::new(next.to_owned()).ok()),
                    event
                        .pointer("/payload/patch/controller_epoch")
                        .and_then(Value::as_u64),
                ) {
                    current.controller_id = controller;
                    current.controller_epoch = epoch;
                }
            }
            arkret_wire::event_kind_str::REALM_AUTHORITY_RESET => {
                if let Some(generation) = event
                    .pointer("/payload/patch/authority_generation")
                    .and_then(Value::as_u64)
                {
                    current.authority_generation = generation;
                }
            }
            arkret_wire::event_kind_str::REALM_AUTHORITY_BASIS_UPDATE => {
                if let Some(digest) = event
                    .pointer("/payload/patch/capability_action_registry_digest")
                    .and_then(Value::as_str)
                    .and_then(|digest| arkret_sdk::Hash::new(digest.to_owned()).ok())
                {
                    current.capability_action_registry_digest = digest;
                }
            }
            _ => {}
        }
    }
    root
}

/// [`realm_authority_root_value_from_events`] over the Realm's full
/// projection entry (`realm_tree_projections[realm_id]`).
pub fn realm_authority_root_value_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
    let events = projections
        .get(realm_id.trim())?
        .get("state")?
        .get("events")?
        .as_array()?;
    realm_authority_root_value_from_events(events)
}

/// [`realm_authority_root_controller_from_events`] over the Realm's full
/// projection entry (`realm_tree_projections[realm_id]`).
pub fn realm_authority_root_controller_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<String> {
    let events = projections
        .get(realm_id.trim())?
        .get("state")?
        .get("events")?
        .as_array()?;
    realm_authority_root_controller_from_events(events)
}

pub fn realm_projection_security_state(body: &Value) -> Option<bool> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&Value::Null),
        body.get("realm").unwrap_or(&Value::Null),
        body.get("metadata").unwrap_or(&Value::Null),
    ] {
        if let Some(state) = direct_security_state(container) {
            return Some(state);
        }
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .chain(
            body.get("state_after")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !kind.contains("realm.create") && !kind.contains("encryption") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event
                .get("payload")
                .and_then(|payload| payload.get("object"))
                .unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event
                .get("content")
                .and_then(|content| content.get("object"))
                .unwrap_or(&Value::Null),
            event.get("object").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(state) = direct_security_state(container) {
                return Some(state);
            }
        }
    }

    // `state_at_window_start.e2ee_epoch = null` means that this projection
    // does not carry a usable window-start epoch hint. It is not evidence that
    // the Realm's create-locked encryption profile is plaintext. Soland emits
    // this null hint even when the same frame contains an encrypted
    // `ak.realm.create` state event, so only a concrete epoch is affirmative
    // security evidence and null remains unknown.
    if body
        .pointer("/state_at_window_start/e2ee_epoch")
        .is_some_and(|epoch| !epoch.is_null())
    {
        return Some(true);
    }

    None
}

pub fn realm_projection_is_encrypted(body: &Value) -> bool {
    realm_projection_security_state(body).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_authority_root_controller_comes_from_create_envelope_actor() {
        let events = json!([{
            "kind": "ak.realm.create",
            "actor_id": "ak:did_core:webvh:z6mkcreator",
            "payload": {
                "object": {
                    "schema": "ak.schema.realm_genesis.v1",
                    "purpose": "collaboration"
                }
            }
        }]);
        assert_eq!(
            realm_authority_root_controller_from_events(events.as_array().unwrap()).as_deref(),
            Some("ak:did_core:webvh:z6mkcreator")
        );
    }

    #[test]
    fn realm_authority_root_replay_follows_owner_transfer_and_reset() {
        let registry_digest = format!("sha256:{}", "a".repeat(64));
        let next_digest = format!("sha256:{}", "b".repeat(64));
        let events = json!([
            {
                "kind": "ak.realm.create",
                "actor_id": "ak:did_core:webvh:z6mkcreator",
                "payload": {
                    "object": {
                        "schema": "ak.schema.realm_genesis.v1",
                        "purpose": "collaboration",
                        "capability_action_registry_digest": registry_digest
                    }
                }
            },
            {
                "kind": "ak.realm.owner.transfer",
                "actor_id": "ak:did_core:webvh:z6mkcreator",
                "payload": {
                    "patch": {
                        "controller_id": "ak:did_core:web:successor.example",
                        "controller_epoch": 1
                    }
                }
            },
            {
                "kind": "ak.realm.authority.reset",
                "actor_id": "ak:did_core:web:successor.example",
                "payload": { "patch": { "authority_generation": 1 } }
            },
            {
                "kind": "ak.realm.authority.basis_update",
                "actor_id": "ak:did_core:web:successor.example",
                "payload": {
                    "patch": { "capability_action_registry_digest": next_digest }
                }
            }
        ]);
        let events = events.as_array().unwrap();
        let root = realm_authority_root_value_from_events(events).unwrap();
        assert_eq!(
            root.controller_id.as_str(),
            "ak:did_core:web:successor.example"
        );
        assert_eq!(root.controller_epoch, 1);
        assert_eq!(root.authority_generation, 1);
        assert_eq!(
            root.capability_action_registry_digest.as_str(),
            format!("sha256:{}", "b".repeat(64))
        );
        // The presentation-grade controller helper follows the same transfer.
        assert_eq!(
            realm_authority_root_controller_from_events(events).as_deref(),
            Some("ak:did_core:web:successor.example")
        );
    }

    #[test]
    fn realm_authority_root_replay_requires_the_create_locked_registry_digest() {
        let events = json!([
            {
                "kind": "ak.realm.create",
                "actor_id": "ak:did_core:webvh:z6mkcreator",
                "payload": { "object": { "schema": "ak.schema.realm_genesis.v1" } }
            },
            {
                "kind": "ak.realm.owner.transfer",
                "payload": {
                    "patch": {
                        "controller_id": "ak:did_core:web:successor.example",
                        "controller_epoch": 1
                    }
                }
            }
        ]);
        // Pre-contract Realm: no root cell, so no value and no transfer effect
        // on the replayed root — but the create-actor controller survives for
        // presentation.
        let events = events.as_array().unwrap();
        assert_eq!(realm_authority_root_value_from_events(events), None);
        assert_eq!(
            realm_authority_root_controller_from_events(events).as_deref(),
            Some("ak:did_core:web:successor.example")
        );
    }

    #[test]
    fn realm_authority_root_controller_does_not_trust_legacy_payload_mirror() {
        let events = json!([{
            "kind": "ak.realm.create",
            "payload": {
                "object": { "created_by": "ak:did_core:webvh:z6mkforged" }
            }
        }]);
        assert_eq!(
            realm_authority_root_controller_from_events(events.as_array().unwrap()),
            None
        );
    }

    #[test]
    fn realm_projection_reads_profile_and_plaintext_visibility() {
        let encrypted = json!({
            "summary": {"encryption_profile": "mls_rfc9420"}
        });
        assert_eq!(realm_projection_security_state(&encrypted), Some(true));
        assert!(realm_projection_is_encrypted(&encrypted));

        let e2ee = json!({
            "plaintext_visibility": {"default": "e2ee"}
        });
        assert_eq!(realm_projection_security_state(&e2ee), Some(true));
        assert!(realm_projection_is_encrypted(&e2ee));

        let plaintext = json!({"encryption_profile": "none"});
        assert_eq!(realm_projection_security_state(&plaintext), Some(false));
        assert!(!realm_projection_is_encrypted(&plaintext));

        let synced_epoch = json!({
            "state_at_window_start": {
                "e2ee_epoch": {"epoch": 0, "key_ref": "mock-key:realm"}
            }
        });
        assert_eq!(realm_projection_security_state(&synced_epoch), Some(true));
        assert!(realm_projection_is_encrypted(&synced_epoch));

        let synced_plaintext = json!({
            "state_at_window_start": {"e2ee_epoch": null}
        });
        assert_eq!(
            realm_projection_security_state(&synced_plaintext),
            None,
            "a missing epoch hint is unknown, not an explicit plaintext profile"
        );

        let real_encrypted_sync_shape = json!({
            "state_at_window_start": {
                "actor_profiles": {},
                "realm_metadata": {"title": "Encrypted Realm"},
                "e2ee_epoch": null
            },
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });
        assert_eq!(
            realm_projection_security_state(&real_encrypted_sync_shape),
            Some(true),
            "the create-locked profile must win over an absent epoch hint"
        );

        assert_eq!(
            realm_projection_security_state(&json!({
                "schema": "ak.schema.realm.v1",
                "title": "projection still syncing"
            })),
            None,
            "an incomplete Realm projection is unknown, not known-plaintext"
        );
    }

    #[test]
    fn strand_projection_uses_explicit_security_before_inheritance() {
        assert_eq!(
            strand_projection_security_state(&json!({"fields": {"encrypted": true}})),
            Some(true)
        );
        assert_eq!(
            strand_projection_security_state(&json!({"object": {"encryption_profile": "none"}})),
            Some(false)
        );
        assert_eq!(
            strand_projection_security_state(
                &json!({"tracks": {"discussion": {"encryption_profile": "none"}}})
            ),
            None
        );
        assert!(strand_projection_is_encrypted(
            &json!({"tracks": {"discussion": {"encryption_profile": "none"}}}),
            true
        ));
        assert!(strand_projection_is_encrypted(&json!({}), true));
        assert!(!strand_projection_is_encrypted(&json!({}), false));
    }

    #[test]
    fn security_projection_follows_space_home_realm() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            json!({"summary": {"encryption_profile": "mls_rfc9420"}}),
        );
        projections.insert(
            "ak:space:s1".to_owned(),
            json!({"schema": "ak.schema.space.v1", "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0"}),
        );
        let body = security_projection_for_scope_id(&projections, "ak:space:s1")
            .expect("realm projection for space");
        assert!(realm_projection_is_encrypted(body));
    }
}
