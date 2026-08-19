//! Decryption adapter for actor-private notification account data.

pub use arkret_sdk::push_rule_core::WatchLevel;
use arkret_wire::AccountDataKey;
pub use chime::{
    DndPeriod, DndSchedule, DndSettings, NotificationDecision, NotificationEvalContext,
    NotificationSound, PushCondition, PushRule, PushRulesConfig, PushRulesRejection,
    evaluate_notification, parse_dnd_settings, parse_push_rules,
};
use serde_json::Value;

pub fn push_rules_from_account_data(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
) -> Option<PushRulesConfig> {
    let value = encrypted_account_data_content(actor_id, entries, AccountDataKey::PUSH_RULES)?;
    match parse_push_rules(&value) {
        Ok(config) => Some(config),
        // A rejected rule set is not "no rules": evaluation must fall back to
        // the built-in policy, and the reason must be visible rather than
        // silently collapsed. v1 accepts client-evaluated rules only.
        Err(rejection) => {
            let code = rejection.wire_code();
            let reason = match &rejection {
                PushRulesRejection::UnsupportedFeature { reason }
                | PushRulesRejection::Malformed { reason } => reason.as_str(),
            };
            tracing::warn!(
                %code,
                %reason,
                "ignoring unusable ak.push_rules account_data; using built-in notification policy"
            );
            None
        }
    }
}

pub fn dnd_settings_from_account_data(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
) -> Option<DndSettings> {
    encrypted_account_data_content(actor_id, entries, AccountDataKey::DND_SCHEDULE)
        .and_then(|value| parse_dnd_settings(&value))
}

fn encrypted_account_data_content(
    actor_id: &str,
    entries: &[arkret_sdk::Event],
    account_data_key: &str,
) -> Option<Value> {
    let entry = entries
        .iter()
        .find(|entry| entry.payload.get("key").and_then(Value::as_str) == Some(account_data_key))?;
    match crate::account_data::decrypt_account_data_entry(
        actor_id,
        account_data_key,
        &entry.payload,
    ) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, %account_data_key, "ignoring undecryptable notification account_data");
            None
        }
    }
}
