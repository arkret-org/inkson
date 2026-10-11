//! Strict decoding of the current account-local state contract.
use super::ClientLocalState;

pub(super) fn decode_account_state(bytes: &[u8]) -> serde_json::Result<ClientLocalState> {
    serde_json::from_slice(bytes)
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) async fn run_browser_retired_account_contract() -> anyhow::Result<()> {
    use crate::secure_key_store::SecureKeyStore;
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await?;
    let namespace = format!("retired-account-test-{}", js_sys::Date::now());
    let key = super::account_state_key(&namespace);
    let mut original = serde_json::to_value(ClientLocalState::default())?;
    original["verified_poll_inputs"] = serde_json::json!([{
        "event":{"event_id":"retired","kind":"ak.message.create","actor_seq":7},
        "accepted_ref":{}
    }]);
    let bytes = serde_json::to_vec(&original)?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    secure
        .store_secret_durable(&key, std::str::from_utf8(&bytes)?)
        .await?;
    let reopened = crate::secure_key_store::IndexedDbSecureKeyStore::new_async("inkson").await?;
    let stored = reopened
        .read_secret_bytes_durable(&key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("durable retired input missing"))?;
    anyhow::ensure!(stored.as_slice() == bytes.as_slice());
    anyhow::ensure!(decode_account_state(&stored).is_err());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_or_retired_signed_records_are_rejected() {
        assert!(decode_account_state(b"{truncated").is_err());
        let mut value = serde_json::to_value(ClientLocalState::default()).unwrap();
        value["verified_poll_inputs"] = serde_json::json!([{
            "event":{"event_id":"retired","kind":"ak.message.create","actor_seq":7,"prev_refs":[]},
            "accepted_ref":{}
        }]);
        assert!(decode_account_state(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn current_state_round_trips() {
        let state = ClientLocalState::default();
        assert_eq!(
            decode_account_state(&serde_json::to_vec(&state).unwrap()).unwrap(),
            state
        );
    }
}
