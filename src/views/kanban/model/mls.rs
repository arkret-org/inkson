use super::*;

/// Borrowed decrypt context threaded into the pure card builders so an
/// encrypted realm's private patch values (`body` / `synthesis` /
/// `description`) can be decrypted on read. All fields are cheap borrows
/// captured from `KanbanPanel` (`state_store.read()`, `account_did`,
/// `device_id`, and the Realm id). `None` (the common, unencrypted
/// case, and every test) means "render plaintext values as-is".
#[derive(Clone, Copy)]
pub(crate) struct MlsDecryptCtx<'a> {
    pub(crate) state_store: &'a LocalStateStore,
    pub(crate) realm_id: &'a str,
    pub(crate) actor_id: &'a str,
    pub(crate) device_id: &'a str,
}

/// Cheap key-only check for the raw MLS payload/envelope shape. Projection and
/// patch wrappers are handled by [`mls_envelope_value`].
pub(crate) fn value_is_raw_mls_envelope(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("scheme").and_then(Value::as_str) == Some("mls-rfc9420") {
        return true;
    }
    object.contains_key("ciphertext") && object.contains_key("content_type")
}

/// Extract a canonical MLS envelope from the value shapes the reducer/projection
/// can hand back to the board UI:
///
/// - raw `EncryptedPayload` / `EncryptedEnvelopeV1`
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

/// Decrypt a single private strand patch value if (and only if) it is an MLS
/// envelope. Returns the decrypted plaintext patch value parsed as JSON
/// (e.g. a string `"…body text…"` or an object `{"body":"…"}`), or `None`
/// when `value` is not an envelope or the decrypt softly fails (no
/// snapshot / wrong device secret / payload that doesn't decrypt). On
/// `None` the caller keeps the original value (plaintext realms) or falls
/// back to a blank field (encrypted-but-locked).
pub(crate) fn decrypt_private_strand_value(
    ctx: &MlsDecryptCtx<'_>,
    value: &Value,
) -> Option<Value> {
    let envelope = mls_envelope_value(value)?;
    let plaintext = crate::views::timeline::try_local_mls_decrypt_core(
        ctx.state_store,
        ctx.realm_id,
        ctx.actor_id,
        ctx.device_id,
        envelope,
    )?;
    serde_json::from_slice::<Value>(&plaintext).ok()
}

/// Render `value` as display text, transparently decrypting it first when
/// it is an MLS envelope and a decrypt context is available. When the
/// value is an envelope but decryption is not possible (no `ctx`, no
/// snapshot, wrong key), the field renders blank rather than leaking the
/// raw envelope JSON through `strand_body_display_text`.
pub(crate) fn private_strand_display_text(
    ctx: Option<&MlsDecryptCtx<'_>>,
    value: Option<&Value>,
) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if value_is_mls_envelope(value) {
        return match ctx.and_then(|ctx| decrypt_private_strand_value(ctx, value)) {
            Some(plaintext) => strand_body_display_text(Some(&plaintext)),
            // Encrypted but un-decryptable: return BLANK (never the raw
            // envelope, never crash). The locked state is surfaced
            // separately via `private_strand_field_locked` so the placeholder
            // text never contaminates `card.body` / the editable draft
            // (which would let an edit overwrite the real ciphertext). See
            // X10.2.
            None => String::new(),
        };
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
/// WITHOUT putting the placeholder text into `card.body` (which the editor
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
    // Decryptable non-empty content (another member's ciphertext) → not
    // locked. Empty decrypted text is treated like a missing plaintext for an
    // encrypted `set`, so the UI does not collapse unreadable private content
    // into a misleading empty state.
    if let Some(plaintext) = ctx.and_then(|ctx| decrypt_private_strand_value(ctx, value))
        && !strand_body_display_text(Some(&plaintext)).trim().is_empty()
    {
        return false;
    }
    // Envelope, no sidecar, can't decrypt → locked.
    true
}

/// X5.2 — resolve the display text for an author-private strand field
/// (`body` / `synthesis`) with a 3-tier precedence:
///
/// 1. **Local plaintext sidecar** (`save_private_plaintext`) — the author's own content, the ONLY
///    source the author can ever see for their own encrypted fields (OpenMLS refuses to decrypt the
///    author's own ciphertext). Stored as the JSON-serialized patch value, so we parse it back and
///    run it through `strand_body_display_text` exactly as the decrypt tier would, keeping
///    write+read symmetric.
/// 2. **Decrypt** (`private_strand_display_text`) — for ciphertext written by *other* members /
///    other leaves synced in, which we *can* decrypt.
/// 3. **Blank** — encrypted-but-unreadable; never leaks the raw envelope.
///
/// `field_path` MUST match the token the writer stored under (the patch
/// key from `collect_encryptable_private_patch_values`: `"body"` /
/// `"synthesis"`).
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
    // Tiers 2 + 3: decrypt another member's ciphertext, else blank.
    private_strand_display_text(ctx, value)
}
