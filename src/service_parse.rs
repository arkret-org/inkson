use serde_json::Value;

use crate::models::ServerDescription;

pub fn parse_server_description(value: Value) -> anyhow::Result<ServerDescription> {
    Ok(serde_json::from_value(value)?)
}
