use serde_json::{Value, json};

fn split_policy_list(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    for value in raw
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_owned());
        }
    }
    values
}

fn normalize_did_method_entry(value: &str) -> Result<String, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    let method = trimmed.strip_prefix("did:").unwrap_or(trimmed.as_str());
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(format!("invalid DID method: {value}"));
    }
    Ok(format!("did:{method}"))
}

fn normalize_principal_id_list(raw: &str, label: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for value in split_policy_list(raw) {
        arkret_sdk::DidCoreId::new(value.clone()).map_err(|err| format!("{label}: {err}"))?;
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
    Ok(values)
}

pub(crate) fn build_principal_admission_join_policy(
    enabled: bool,
    methods_raw: &str,
    allowed_ids_raw: &str,
    denied_ids_raw: &str,
) -> Result<Option<Value>, String> {
    if !enabled {
        return Ok(None);
    }
    let mut methods = Vec::new();
    for method in split_policy_list(methods_raw) {
        let method = normalize_did_method_entry(&method)?;
        if !methods.iter().any(|existing| existing == &method) {
            methods.push(method);
        }
    }
    let allowed_ids = normalize_principal_id_list(allowed_ids_raw, "allowed principal id")?;
    let denied_ids = normalize_principal_id_list(denied_ids_raw, "denied principal id")?;
    if methods.is_empty() && allowed_ids.is_empty() && denied_ids.is_empty() {
        return Err("principal admission requires a method, allowlist id, or denylist id".into());
    }
    let mut gate = json!({
        "gate_id": "principal-admission",
        "kind": "principal_admission",
        "auto_resolve": true
    });
    if !methods.is_empty() {
        gate["allowed_did_methods"] = json!(methods);
    }
    if !allowed_ids.is_empty() {
        gate["allowed_principal_ids"] = json!(allowed_ids);
    }
    if !denied_ids.is_empty() {
        gate["denied_principal_ids"] = json!(denied_ids);
    }
    Ok(Some(json!({
        "gates": [gate],
        "combinator": "all"
    })))
}

#[cfg(test)]
mod principal_admission_policy_tests {
    use super::*;

    #[test]
    fn principal_admission_policy_normalizes_method() {
        let policy = build_principal_admission_join_policy(true, "webvh", "", "")
            .unwrap()
            .unwrap();
        assert_eq!(
            policy["gates"][0]["allowed_did_methods"],
            json!(["did:webvh"])
        );
        assert_eq!(policy["gates"][0]["kind"], "principal_admission");
    }

    #[test]
    fn principal_admission_policy_requires_selector() {
        let err = build_principal_admission_join_policy(true, "", "", "").unwrap_err();
        assert!(err.contains("requires"));
    }
}
