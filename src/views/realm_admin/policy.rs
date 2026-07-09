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

fn normalize_did_list(raw: &str, label: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for value in split_policy_list(raw) {
        arkret_sdk::Did::new(value.clone()).map_err(|err| format!("{label}: {err}"))?;
        if !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    }
    Ok(values)
}

pub(crate) fn build_principal_admission_join_policy(
    enabled: bool,
    methods_raw: &str,
    allowed_dids_raw: &str,
    denied_dids_raw: &str,
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
    let allowed_dids = normalize_did_list(allowed_dids_raw, "allowed principal DID")?;
    let denied_dids = normalize_did_list(denied_dids_raw, "denied principal DID")?;
    if methods.is_empty() && allowed_dids.is_empty() && denied_dids.is_empty() {
        return Err("principal admission requires a method, allowlist DID, or denylist DID".into());
    }
    let mut gate = json!({
        "gate_id": "principal-admission",
        "kind": "principal_admission",
        "auto_resolve": true
    });
    if !methods.is_empty() {
        gate["allowed_did_methods"] = json!(methods);
    }
    if !allowed_dids.is_empty() {
        gate["allowed_principal_dids"] = json!(allowed_dids);
    }
    if !denied_dids.is_empty() {
        gate["denied_principal_dids"] = json!(denied_dids);
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
