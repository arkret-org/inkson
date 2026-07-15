//! Realm-level recovery flow (RRK): reconstruct history with the offline
//! recovery key (encryption-and-audit.md §2.10.8 storage & recovery read path).
//!
//! When every member device is lost / everyone has left, an RRK holder takes the
//! offline recovery key out, opens the durable RRK-targeted `ak.realm_key.share`
//! Events from the Realm event log, and recovers each epoch's `history_secret`
//! (→ `K_content[N]` → decrypt history per §2.10.1).
//!
//! Two credential paths (§2.3.1):
//! - `org_recovery_key`: a single 24-word recovery key derives the RRK X25519 private key directly
//!   ([`crate::mls::durability::derive_rrk_keypair_from_recovery_key`]).
//! - `threshold` (k-of-n): the RRK private key is reconstructed out-of-band via the key-management
//!   §8 threshold recovery policy; once reconstructed, the recovery key text is the same canonical
//!   24-word form and lands the same way.
//!
//! Input: the durable `ak.realm_key.share` Events addressed to the RRK (recovered
//! from the Realm event log). This editor accepts them as a pasted JSON array so
//! an operator can drive recovery from an exported log; wiring an automatic pull
//! from a soland recovery-read endpoint is a follow-up (aligns with the soland
//! durability projection task).

use dioxus::prelude::*;
use serde_json::Value;

/// Parse the pasted JSON: either a top-level array of share Events, or an object
/// with a `shares` / `events` array. Each element may be the Event or its
/// `{ "content": { "ciphertext": ... } }` form (both are handled downstream).
fn parse_share_events(raw: &str) -> Result<Vec<Value>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("paste the RRK-targeted ak.realm_key.share events".to_owned());
    }
    let value: Value =
        serde_json::from_str(trimmed).map_err(|err| format!("invalid JSON: {err}"))?;
    let events = match value {
        Value::Array(events) => events,
        Value::Object(ref object) => object
            .get("shares")
            .or_else(|| object.get("events"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![value.clone()]),
        other => vec![other],
    };
    Ok(events)
}

/// Realm-level recovery card. Mount inside the Realm admin Security section.
#[component]
pub fn DurabilityRecoveryPanel(realm_id: String) -> Element {
    // A4 — state_store from session context instead of a prop.
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut recovery_key = use_signal(String::new);
    let mut shares_raw = use_signal(String::new);
    let mut status = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "realm-durability-recovery",
            div { class: "event-head",
                span { "Realm history recovery (RRK)" }
                span { class: "badge amber", "offline recovery key" }
            }
            div { class: "muted",
                "全体成员设备失效或全员离职后，用离线恢复密钥（24 词；门限模式先按 key-management §8 重组私钥）解开 RRK 封存的 ak.realm_key.share，还原各 epoch 的 history_secret 以解密历史。"
            }

            label { r#for: "rrk-recovery-key-input", "Recovery key (24 words)" }
            textarea {
                id: "rrk-recovery-key-input",
                "data-testid": "rrk-recovery-key-input",
                rows: "2",
                value: "{recovery_key}",
                oninput: move |evt| recovery_key.set(evt.value()),
            }

            label { r#for: "rrk-recovery-shares-input", "RRK ak.realm_key.share events (JSON)" }
            div { class: "muted",
                "粘贴从 Realm 事件日志取回的 RRK-targeted ak.realm_key.share 事件（JSON 数组）。"
            }
            textarea {
                id: "rrk-recovery-shares-input",
                "data-testid": "rrk-recovery-shares-input",
                rows: "4",
                value: "{shares_raw}",
                oninput: move |evt| shares_raw.set(evt.value()),
            }

            button {
                class: "primary",
                "data-testid": "rrk-recovery-apply",
                onclick: move |_| {
                    let realm_id = realm_id.clone();
                    let key_text = recovery_key();
                    let shares_text = shares_raw();
                    let (rrk_private_key, _rrk_public) =
                        match crate::mls::durability::derive_rrk_keypair_from_recovery_key(&key_text)
                        {
                            Ok(keypair) => keypair,
                            Err(err) => {
                                status.set(format!("恢复密钥无效: {err}"));
                                return;
                            }
                        };
                    let shares = match parse_share_events(&shares_text) {
                        Ok(shares) => shares,
                        Err(err) => {
                            status.set(format!("解析 share 失败: {err}"));
                            return;
                        }
                    };
                    let recovered = crate::mls::durability::recover_history_from_rrk_shares(
                        &rrk_private_key,
                        &shares,
                    );
                    if recovered.is_empty() {
                        status.set(
                            "未能用该恢复密钥打开任何 share（密钥与封存公钥不匹配，或 share 为空）。"
                                .to_owned(),
                        );
                        return;
                    }
                    let count = recovered.len();
                    spawn(async move {
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        let pending = {
                            state_store.read().prepare_history_secrets(
                                secure_store.as_ref(),
                                realm_id,
                                recovered,
                            )
                        };
                        let pending = match pending {
                            Ok(Some(pending)) => pending,
                            Ok(None) => {
                                status.set("恢复结果不包含有效的 history_secret。".to_owned());
                                return;
                            }
                            Err(error) => {
                                status.set(format!("读取 history_secret 安全存储失败: {error}"));
                                return;
                            }
                        };
                        if let Err(error) = pending.persist(secure_store.as_ref()).await {
                            status.set(format!("持久化 history_secret 失败: {error}"));
                            return;
                        }
                        state_store.write().publish_history_secrets(pending);
                        status.set(format!(
                            "已恢复并安装 {count} 个 epoch 的 history_secret；历史内容现可在本设备解密。"
                        ));
                    });
                },
                "Recover history"
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "rrk-recovery-status", "{status}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_array_form() {
        let raw = r#"[{"content":{"ciphertext":"abc"}}]"#;
        let events = parse_share_events(raw).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn parses_wrapped_shares_form() {
        let raw = json!({ "shares": [{ "content": { "ciphertext": "abc" } }] }).to_string();
        let events = parse_share_events(&raw).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(parse_share_events("   ").is_err());
    }
}
