//! Decryption adapter for actor-private notification account data.

pub use chime::{
    DndPeriod, DndSchedule, DndSettings, NotificationDecision, NotificationEvalContext,
    NotificationSound, PushCondition, PushRule, PushRulesConfig, WatchLevel, evaluate_notification,
    parse_dnd_settings, parse_push_rules,
};
use serde_json::Value;

pub fn push_rules_from_account_data(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
) -> Option<PushRulesConfig> {
    encrypted_account_data_content(actor_id, entries, "ak.push_rules")
        .and_then(|value| parse_push_rules(&value))
}

pub fn dnd_settings_from_account_data(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
) -> Option<DndSettings> {
    encrypted_account_data_content(actor_id, entries, "ak.dnd_schedule")
        .and_then(|value| parse_dnd_settings(&value))
}

fn encrypted_account_data_content(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
    data_type: &str,
) -> Option<Value> {
    let entry = entries
        .iter()
        .find(|entry| entry.payload.get("key").and_then(Value::as_str) == Some(data_type))?;
    match crate::account_data::decrypt_account_data_entry(actor_id, data_type, &entry.payload) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, %data_type, "ignoring undecryptable notification account_data");
            None
        }
    }
}
