use super::*;

/// Borrowed decrypt context threaded into the pure card builders so an
/// encrypted realm's author-side plaintext cache can be read without cloning
/// the local store. Projected ciphertext stays opaque until its verified outer
/// Event context is threaded through the projection.
#[derive(Clone, Copy)]
pub(crate) struct MlsDecryptCtx<'a> {
    pub(crate) state_store: &'a LocalStateStore,
    pub(crate) realm_id: &'a str,
}

/// Build a render-time decrypt context only when entering the MLS runtime is
/// locally safe. A persisted Realm snapshot is wrapped by the account MLS
/// secret; when that secret is absent, attempting every encrypted historical
/// patch would rescan all secret versions for every field and block the wasm
/// main thread. Keep the envelopes opaque until recovery restores the secret.
///
/// A Realm with no local snapshot is still allowed through because exporter
/// history-secret decryption does not require the snapshot/account wrapper.
pub(crate) fn mls_decrypt_ctx_if_ready<'a>(
    state_store: &'a LocalStateStore,
    realm_id: &'a str,
    actor_id: &'a str,
) -> Option<MlsDecryptCtx<'a>> {
    let snapshot_requires_account_secret = state_store.mls_snapshot_for(realm_id).is_some();
    if snapshot_requires_account_secret {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let account_secret_available = matches!(
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), actor_id),
            Ok(Some(_))
        );
        if !should_enter_mls_decrypt_runtime(
            snapshot_requires_account_secret,
            account_secret_available,
        ) {
            return None;
        }
    }
    Some(MlsDecryptCtx {
        state_store,
        realm_id,
    })
}

fn should_enter_mls_decrypt_runtime(
    snapshot_requires_account_secret: bool,
    account_secret_available: bool,
) -> bool {
    !snapshot_requires_account_secret || account_secret_available
}

/// Cheap key-only check for the raw MLS payload/envelope shape. Projection and
/// patch wrappers are handled by [`mls_envelope_value`].
pub(crate) fn value_is_raw_mls_envelope(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("scheme").and_then(Value::as_str) == Some("mls_rfc9420") {
        return true;
    }
    object.contains_key("ciphertext") && object.contains_key("content_type")
}

/// Extract a canonical MLS envelope from the value shapes the reducer/projection
/// can hand back to the board UI:
///
/// - raw `EncryptedPayload` / `EncryptedEnvelope`
/// - `{ "encrypted_content": <envelope> }`
/// - patch/set wrappers such as `{ "$op": "set", "value": <envelope> }`
///
/// This intentionally does not recurse through arbitrary object fields, so a
/// plaintext business object containing unrelated keys is not treated as E2EE.
pub(crate) fn mls_envelope_value(value: &Value) -> Option<&Value> {
    if value_is_raw_mls_envelope(value) {
        return Some(value);
    }
    let object = value.as_object()?;
    for key in ["encrypted_content", "encrypted_payload", "value"] {
        if let Some(child) = object.get(key)
            && let Some(envelope) = mls_envelope_value(child)
        {
            return Some(envelope);
        }
    }
    None
}

/// Cheap key-only check: is `value` an MLS-encrypted envelope, possibly wrapped
/// by a projection or patch operation?
pub(crate) fn value_is_mls_envelope(value: &Value) -> bool {
    mls_envelope_value(value).is_some()
}

/// Render `value` as display text, transparently decrypting it first when
/// it is plaintext. Projected encrypted values stay opaque because they do
/// not carry the verified outer Event context required to reconstruct the
/// authenticated header. The author-side plaintext cache is handled by
/// [`private_strand_field_text`].
pub(crate) fn private_strand_display_text(
    _ctx: Option<&MlsDecryptCtx<'_>>,
    value: Option<&Value>,
) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if value_is_mls_envelope(value) {
        return String::new();
    }
    strand_body_display_text(Some(value))
}

pub(crate) fn private_plaintext_display_text(plaintext: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<Value>(plaintext) {
        return strand_body_display_text(Some(&parsed));
    }
    plaintext.to_owned()
}

/// X10.2 — true when a private field IS an MLS envelope that this device
/// cannot currently read: no local plaintext sidecar AND decryption is not
/// possible (author's own ciphertext / fresh browser before MLS unlock).
/// The display layer renders [`MLS_LOCKED_FIELD_PLACEHOLDER`] in this case so
/// the user can tell "encrypted, unlock to view" apart from "no content" —
/// WITHOUT putting the placeholder text into `card.synthesis` (which the editor
/// copies and could re-save, corrupting the real encrypted content).
pub(crate) fn private_strand_field_locked(
    ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> bool {
    let Some(value) = value else {
        return false;
    };
    if !value_is_mls_envelope(value) {
        return false;
    }
    // Non-empty sidecar hit → readable, not locked. Empty sidecars are not
    // useful for an encrypted `set` value; treat them as missing so the UI
    // does not confuse encrypted-but-unreadable content with "no content".
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, strand_id, field_path)
        && !private_plaintext_display_text(&plaintext).trim().is_empty()
    {
        return false;
    }
    // Envelope with no author-side plaintext is locked until its verified
    // outer Event context is available to the projection.
    true
}

/// X5.2 — resolve the display text for an author-private strand field
/// (canonically `encrypted_content`) with a 3-tier precedence:
///
/// 1. **Local plaintext sidecar** (`save_private_plaintext`) — the author's own content, the ONLY
///    source the author can ever see for their own encrypted fields (OpenMLS refuses to decrypt the
///    author's own ciphertext). Stored as the JSON-serialized patch value, so we parse it back and
///    run it through `strand_body_display_text` exactly as the decrypt tier would, keeping
///    write+read symmetric.
/// 2. **Blank** — encrypted content without its verified outer Event context; never leaks the raw
///    envelope.
///
/// `field_path` MUST match the token the writer stored under — the ENCRYPTED
/// patch key (`kanban_encrypted_patch_path`): `"encrypted_content"` for the
/// Strand Description, or `"tracks.synthesis.encrypted_content"` for the
/// Synthesis track.
pub(crate) fn private_strand_field_text(
    ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> String {
    // Tier 1: author's own plaintext sidecar (local-only).
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, strand_id, field_path)
    {
        let text = private_plaintext_display_text(&plaintext);
        if !text.trim().is_empty() {
            return text;
        }
    }
    // Tier 2: encrypted content remains opaque without verified Event context.
    private_strand_display_text(ctx, value)
}

#[cfg(test)]
mod readiness_tests {
    use super::should_enter_mls_decrypt_runtime;

    #[test]
    fn persisted_snapshot_without_account_secret_never_enters_render_time_mls_runtime() {
        assert!(!should_enter_mls_decrypt_runtime(true, false));
        assert!(should_enter_mls_decrypt_runtime(true, true));
        // History-secret-only reads remain possible before a local snapshot is
        // installed, and do not require the account snapshot wrapper.
        assert!(should_enter_mls_decrypt_runtime(false, false));
    }
}
