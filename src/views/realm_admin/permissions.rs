use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RealmMemberPermissions {
    pub(crate) loaded: bool,
    pub(crate) can_invite: bool,
    pub(crate) can_remove: bool,
}

pub(crate) fn authz_json_allowed(value: &Value) -> bool {
    value
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            value
                .get("decision")
                .and_then(Value::as_str)
                .map(|decision| matches!(decision, "allow" | "allowed"))
                .unwrap_or(false)
        })
}
