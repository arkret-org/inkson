use serde_json::Value;

use crate::models::{DirectoryDescription, ResolveRealmOutcome, ServerDescription};

pub fn parse_server_description(value: Value) -> anyhow::Result<ServerDescription> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_sync_describe(value: Value) -> anyhow::Result<cokret_sdk::models::SyncDescription> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_directory_describe(value: Value) -> anyhow::Result<DirectoryDescription> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_resolve_realm(value: Value) -> anyhow::Result<ResolveRealmOutcome> {
    Ok(serde_json::from_value(value)?)
}
