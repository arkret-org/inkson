pub(crate) fn validate_join_rule_v1(join_rule: &str) -> anyhow::Result<&str> {
    match join_rule {
        "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed" => {
            Ok(join_rule)
        }
        _ => Err(anyhow::anyhow!(
            "unsupported current-v1 join_rule: {join_rule}"
        )),
    }
}
