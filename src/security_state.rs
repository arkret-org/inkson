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
/// `ak.realm.create` is the only registered writer of
/// `ak.component.realm.authority_root.v1` in v1 (contract-registry.json), and
/// its registered `value_projection` sets `controller_id =
/// payload.object.created_by`. This reads that one cell input; it is not the
/// forbidden `realm_state.owner` / membership fallback — those are projection
/// mirrors of a different fact, and post-P1 realm projections no longer carry
/// them at all.
pub fn realm_authority_root_controller_from_events(events: &[Value]) -> Option<String> {
    events.iter().rev().find_map(|event| {
        let kind = event
            .get("kind")
            .or_else(|| event.get("event_kind"))
            .and_then(Value::as_str)?;
        if kind != arkret_sdk::events::EventKind::REALM_CREATE {
            return None;
        }
        event
            .get("payload")
            .unwrap_or(event)
            .get("object")?
            .get("created_by")
            .and_then(Value::as_str)
            .map(|created_by| created_by.trim().to_owned())
    })
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
            "ak:realm:r1".to_owned(),
            json!({"summary": {"encryption_profile": "mls_rfc9420"}}),
        );
        projections.insert(
            "ak:space:s1".to_owned(),
            json!({"schema": "ak.schema.space.v1", "realm_id": "ak:realm:r1"}),
        );
        let body = security_projection_for_scope_id(&projections, "ak:space:s1")
            .expect("realm projection for space");
        assert!(realm_projection_is_encrypted(body));
    }
}
