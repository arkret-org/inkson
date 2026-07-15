use serde_json::Value;

use crate::models::ServiceDescribe;

pub fn parse_server_description(value: Value) -> anyhow::Result<ServiceDescribe> {
    Ok(serde_json::from_value(value)?)
}
