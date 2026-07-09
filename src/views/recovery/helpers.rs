//! Passkey-wrap AAD construction and clipboard helper.

use dioxus::prelude::*;

use super::types::PasskeyRecoveryWrap;

pub(crate) fn passkey_wrap_aad(
    account_id: &str,
    wrap: &PasskeyRecoveryWrap,
) -> anyhow::Result<Vec<u8>> {
    crate::canonical::canonical_json_bytes(&serde_json::json!({
        "schema": "ak.local.recovery_passkey_wrap.v1",
        "account_id": account_id,
        "wrap_id": wrap.wrap_id,
        "credential_id": wrap.credential_id_b64,
        "rp_id": wrap.rp_id,
        "recovery_key_fingerprint": wrap.recovery_key_fingerprint,
        "created_at": wrap.created_at,
    }))
    .map_err(|err| anyhow::anyhow!("passkey wrap aad canonical json: {err}"))
}

/// Copy the 24-word Recovery Key to the clipboard so the user never has to
/// hand-select it (a partial selection silently drops words). Prefers the async
/// Clipboard API and falls back to `execCommand` on insecure contexts.
pub(crate) fn copy_recovery_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}
