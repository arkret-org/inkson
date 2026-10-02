//! Review only changed trust fields; retain full values for explicit inspection.

use std::collections::BTreeSet;

use serde_json::Value;

use super::ConnectionTrustChange;

pub(crate) struct ConnectionChangeDetail {
    pub label: String,
    pub previous: String,
    pub candidate: String,
}

pub(crate) fn connection_changes(change: &ConnectionTrustChange) -> Vec<ConnectionChangeDetail> {
    let mut details = Vec::new();
    for (label, previous, candidate) in [
        (
            "Server identity",
            change.previous.service_id.to_string(),
            change.candidate.service_id.to_string(),
        ),
        (
            "Trust domain",
            change.previous.trust_domain.to_string(),
            change.candidate.trust_domain.to_string(),
        ),
    ] {
        if previous != candidate {
            details.push(ConnectionChangeDetail {
                label: label.into(),
                previous,
                candidate,
            });
        }
    }
    // Walk serialized metadata so optional fields, additions/removals, and
    // future authentication fields cannot silently disappear from the review.
    let previous = serde_json::to_value(&change.previous.auth_metadata)
        .expect("authentication metadata is serializable");
    let candidate = serde_json::to_value(&change.candidate.auth_metadata)
        .expect("authentication metadata is serializable");
    changed_fields(&previous, &candidate, "", &mut details);
    details
}

fn changed_fields(
    previous: &Value,
    candidate: &Value,
    label: &str,
    details: &mut Vec<ConnectionChangeDetail>,
) {
    if previous == candidate {
        return;
    }
    if previous.is_object() || candidate.is_object() {
        let keys: BTreeSet<_> = [previous, candidate]
            .into_iter()
            .filter_map(Value::as_object)
            .flat_map(|object| object.keys())
            .collect();
        for key in keys {
            let field = match key.as_str() {
                "account_authority" => "Sign-in service",
                "origin" => "Origin",
                "gate_account_base_url" => "URL",
                "methods" => "Sign-in method",
                "method" => "Type",
                "issuer_uri" => "Issuer",
                "provider_uri" => "Provider",
                "openid_configuration_url" => "Provider discovery",
                "client_id" => "Client",
                "scopes" => "Permissions",
                "grant_exchange" => "Grant exchange",
                "kind" => "Type",
                "did_binding_methods" => "Identity binding methods",
                _ => key.as_str(),
            };
            let field_label = if label.is_empty() {
                field.into()
            } else {
                format!("{label} · {field}")
            };
            changed_fields(&previous[key], &candidate[key], &field_label, details);
        }
    } else if label == "Sign-in method" {
        changed_methods(previous, candidate, details);
    } else {
        details.push(ConnectionChangeDetail {
            label: label.into(),
            previous: display_value(previous),
            candidate: display_value(candidate),
        });
    }
}

fn changed_methods(previous: &Value, candidate: &Value, details: &mut Vec<ConnectionChangeDetail>) {
    let previous = previous.as_array().map(Vec::as_slice).unwrap_or_default();
    let candidate = candidate.as_array().map(Vec::as_slice).unwrap_or_default();
    let count = previous.len().max(candidate.len());
    let mut remaining: Vec<_> = candidate.iter().enumerate().collect();
    let mut changed = Vec::new();
    // Canonical sorting can move a method when its client/issuer changes.
    // Remove exact matches first so unchanged methods never become false diffs.
    for (index, method) in previous.iter().enumerate() {
        if let Some(position) = remaining.iter().position(|(_, value)| *value == method) {
            remaining.remove(position);
        } else {
            changed.push((index, method));
        }
    }
    let label = |index: usize, method: &Value| {
        if count == 1 {
            "Sign-in method".into()
        } else {
            format!(
                "Sign-in method {} ({})",
                index + 1,
                display_value(&method["method"])
            )
        }
    };
    for (index, method) in changed {
        let position = remaining
            .iter()
            .position(|(_, value)| {
                value["method"] == method["method"]
                    && value["issuer_uri"] == method["issuer_uri"]
                    && value["provider_uri"] == method["provider_uri"]
            })
            .or_else(|| {
                remaining
                    .iter()
                    .position(|(_, value)| value["method"] == method["method"])
            });
        if let Some(position) = position {
            let (candidate_index, candidate_method) = remaining.remove(position);
            changed_fields(
                method,
                candidate_method,
                &label(candidate_index, candidate_method),
                details,
            );
        } else {
            changed_fields(method, &Value::Null, &label(index, method), details);
        }
    }
    for (index, method) in remaining {
        changed_fields(&Value::Null, method, &label(index, method), details);
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "Not configured".into(),
        Value::String(value) => value.clone(),
        Value::Array(values) if values.is_empty() => "None".into(),
        Value::Array(values) => values
            .iter()
            .map(display_value)
            .collect::<Vec<_>>()
            .join(", "),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use arkret_sdk::StationConnectionBinding;
    use serde_json::json;

    use super::*;

    fn binding() -> StationConnectionBinding {
        serde_json::from_value(json!({
            "base_url": "https://station.example/",
            "service_id": "ak:did_core:webvh:z6mkfixture",
            "trust_domain": "ak:trust_domain:station.example",
            "auth_metadata": {
                "account_authority": { "origin": "https://auth.example", "gate_account_base_url": "https://auth.example/_arkret/gate/account" },
                "methods": [{ "method": "oidc", "issuer_uri": "https://auth.example/", "client_id": "old-client", "scopes": ["openid", "profile"], "grant_exchange": { "kind": "account_handoff" } }]
            }
        })).unwrap()
    }

    #[test]
    fn identity_only_change_omits_same_trust_domain_and_authentication() {
        let previous = binding();
        let mut candidate = previous.clone();
        candidate.service_id = arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkchanged").unwrap();
        let details = connection_changes(&ConnectionTrustChange {
            previous,
            candidate,
        });
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].label, "Server identity");
        assert_eq!(details[0].previous, "ak:did_core:webvh:z6mkfixture");
        assert_eq!(details[0].candidate, "ak:did_core:webvh:z6mkchanged");
    }

    #[test]
    fn authentication_change_only_shows_changed_fields() {
        let previous = binding();
        let mut candidate = previous.clone();
        candidate.auth_metadata.methods[0].client_id = Some("new-client".into());
        candidate.auth_metadata.methods[0].provider_uri = Some("https://provider.example/".into());
        let details = connection_changes(&ConnectionTrustChange {
            previous,
            candidate,
        });
        assert_eq!(details.len(), 2);
        assert_eq!(details[0].label, "Sign-in method · Client");
        assert_eq!(details[0].previous, "old-client");
        assert_eq!(details[0].candidate, "new-client");
        assert_eq!(details[1].previous, "Not configured");
        assert_eq!(details[1].candidate, "https://provider.example/");
    }

    #[test]
    fn removed_authority_and_method_keep_previous_values_visible() {
        let previous = binding();
        let mut candidate = previous.clone();
        candidate.auth_metadata.account_authority = None;
        candidate.auth_metadata.methods.clear();
        let details = connection_changes(&ConnectionTrustChange {
            previous,
            candidate,
        });
        assert_eq!(details.len(), 7);
        assert!(
            details
                .iter()
                .all(|detail| detail.candidate == "Not configured")
        );
        assert!(
            details
                .iter()
                .any(|detail| detail.previous == "account_handoff")
        );
        assert!(
            details
                .iter()
                .any(|detail| detail.previous == "openid, profile")
        );
    }

    #[test]
    fn reordered_methods_do_not_create_changes_for_unchanged_providers() {
        let mut previous = binding();
        let mut second_method = previous.auth_metadata.methods[0].clone();
        second_method.client_id = Some("second-client".into());
        previous.auth_metadata.methods.push(second_method);
        let mut candidate = previous.clone();
        candidate.auth_metadata.methods[0].client_id = Some("third-client".into());
        candidate.auth_metadata.methods.swap(0, 1);
        let details = connection_changes(&ConnectionTrustChange {
            previous,
            candidate,
        });
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].label, "Sign-in method 2 (oidc) · Client");
        assert_eq!(details[0].previous, "old-client");
        assert_eq!(details[0].candidate, "third-client");
    }

    #[test]
    fn unchanged_connection_has_no_details() {
        let previous = binding();
        assert!(
            connection_changes(&ConnectionTrustChange {
                candidate: previous.clone(),
                previous
            })
            .is_empty()
        );
    }
}
