use std::collections::BTreeMap;

use serde_json::Value;

fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| non_empty_string(value.get(*key)))
}

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
    !matches!(
        normalized.as_str(),
        "" | "none" | "plain" | "plaintext" | "unencrypted" | "disabled" | "off" | "false"
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

fn security_state_token(token: &str) -> Option<bool> {
    let normalized = token.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "encrypted" | "e2ee" | "mls" | "mls_rfc9420" | "secure" | "ciphertext" => Some(true),
        "none" | "plain" | "plaintext" | "unencrypted" | "insecure" | "disabled" | "off"
        | "false" => Some(false),
        _ => None,
    }
}

fn direct_security_state(value: &Value) -> Option<bool> {
    if value.get("encrypted_payload").is_some()
        || value
            .get("content")
            .and_then(|content| content.get("encrypted_payload"))
            .is_some()
    {
        return Some(true);
    }
    if let Some(encrypted) = bool_field(
        value,
        &[
            "encrypted",
            "is_encrypted",
            "e2ee",
            "end_to_end_encrypted",
            "secure",
            "is_secure",
        ],
    ) {
        return Some(encrypted);
    }
    if let Some(profile) = string_field(
        value,
        &["encryption_profile", "encryptionProfile", "encryption"],
    ) {
        return Some(encryption_profile_is_encrypted(&profile));
    }
    if let Some(state) = string_field(
        value,
        &["security_state", "security", "crypto_state", "privacy_mode"],
    )
    .and_then(|state| security_state_token(&state))
    {
        return Some(state);
    }
    value
        .get("plaintext_visibility")
        .and_then(plaintext_visibility_value)
        .and_then(|visibility| plaintext_visibility_security_state(&visibility))
}

pub fn flow_projection_security_state(value: &Value) -> Option<bool> {
    let paths: &[&[&str]] = &[
        &[],
        &["object"],
        &["flow"],
        &["body"],
        &["fields"],
        &["scope"],
        &["scope_circle"],
        &["metadata"],
        &["content"],
        &["tracks"],
        &["tracks", "discussion"],
        &["tracks", "synthesis"],
    ];
    paths
        .iter()
        .filter_map(|path| path_value(value, path))
        .find_map(direct_security_state)
}

pub fn flow_projection_is_encrypted(value: &Value, inherited_realm_encrypted: bool) -> bool {
    flow_projection_security_state(value).unwrap_or(inherited_realm_encrypted)
}

pub fn projection_for_scope_id<'a>(
    projections: &'a BTreeMap<String, Value>,
    scope_id: &str,
) -> Option<&'a Value> {
    let scope_id = scope_id.trim();
    if scope_id.is_empty() {
        return None;
    }
    projections.get(scope_id).or_else(|| {
        scope_id
            .strip_prefix("cx:space:")
            .and_then(|suffix| projections.get(&format!("cx:realm:{suffix}")))
            .or_else(|| {
                scope_id
                    .strip_prefix("cx:realm:")
                    .and_then(|suffix| projections.get(&format!("cx:space:{suffix}")))
            })
    })
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

pub fn realm_projection_is_encrypted(body: &Value) -> bool {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&Value::Null),
        body.get("realm").unwrap_or(&Value::Null),
        body.get("metadata").unwrap_or(&Value::Null),
    ] {
        if let Some(state) = direct_security_state(container) {
            return state;
        }
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
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
                return state;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn realm_projection_reads_profile_and_plaintext_visibility() {
        assert!(realm_projection_is_encrypted(&json!({
            "summary": {"encryption_profile": "mls_rfc9420"}
        })));
        assert!(realm_projection_is_encrypted(&json!({
            "plaintext_visibility": {"default": "e2ee"}
        })));
        assert!(!realm_projection_is_encrypted(&json!({
            "encryption_profile": "none"
        })));
    }

    #[test]
    fn flow_projection_uses_explicit_security_before_inheritance() {
        assert_eq!(
            flow_projection_security_state(&json!({"fields": {"encrypted": true}})),
            Some(true)
        );
        assert_eq!(
            flow_projection_security_state(&json!({"object": {"encryption_profile": "none"}})),
            Some(false)
        );
        assert!(flow_projection_is_encrypted(&json!({}), true));
        assert!(!flow_projection_is_encrypted(&json!({}), false));
    }

    #[test]
    fn security_projection_follows_space_home_realm() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "cx:realm:r1".to_owned(),
            json!({"summary": {"encryption_profile": "mls_rfc9420"}}),
        );
        projections.insert(
            "cx:space:s1".to_owned(),
            json!({"schema": "cx.schema.space.v1", "realm_id": "cx:realm:r1"}),
        );
        let body = security_projection_for_scope_id(&projections, "cx:space:s1")
            .expect("realm projection for space");
        assert!(realm_projection_is_encrypted(body));
    }
}
