use super::*;

/// Borrowed decrypt context threaded into the pure card builders so an
/// encrypted realm's author-side plaintext cache can be read without cloning
/// the local store. Projected ciphertext stays opaque until its verified outer
/// Event context is threaded through the projection.
#[derive(Clone, Copy)]
pub(crate) struct MlsDecryptCtx<'a> {
    pub(crate) state_store: &'a LocalStateStore,
    pub(crate) realm_id: &'a str,
    pub(crate) identity: Option<(&'a arkret_sdk::AccountId, &'a str)>,
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
    authority: &'a arkret_sdk::AccountId,
    device_id: &'a str,
) -> Option<MlsDecryptCtx<'a>> {
    let snapshot_requires_account_secret = state_store.mls_checkpoint_for(realm_id).is_some();
    if snapshot_requires_account_secret {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let account_secret_available = matches!(
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority),
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
        identity: Some((authority, device_id)),
    })
}

/// A remote patch must be decrypted using its original signed Event, never a
/// projection's claimed sender or an unrelated author-side field cache.
pub(crate) fn private_strand_event_field_text(
    ctx: &MlsDecryptCtx<'_>,
    event_value: &Value,
    strand_id: &str,
    field_path: &str,
    value: &Value,
) -> Option<String> {
    let (authority, device_id) = ctx.identity?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    let event: arkret_sdk::Event = serde_json::from_value(event_value.clone()).ok()?;
    if event.kind != arkret_sdk::EventKind::StrandUpdate
        || event.realm_id.as_str() != ctx.realm_id
        || event.scope_ref.realm_id_opt() != Some(&event.realm_id)
        || event.payload.get("target_ref")?.as_str()? != strand_id
    {
        return None;
    }
    let patch = event.payload.get("patch")?.as_object()?;
    let signed_op = patch_op_for_private_path(patch, field_path)?;
    let signed_op: arkret_wire::patch::PatchOp =
        serde_json::from_value(signed_op.into_owned()).ok()?;
    if signed_op.op() != arkret_wire::patch::PatchOpKind::Set || signed_op.value() != Some(value) {
        return None;
    }
    let warn_pending = |reason: &str| {
        crate::mls::runtime::warn_mls_decrypt_once(
            ctx.realm_id,
            event.event_id.event_digest().as_str(),
            value
                .pointer("/encryption_context/epoch")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            ctx.state_store
                .mls_checkpoint_for_scope(&event.scope_ref)
                .map(|snapshot| snapshot.epoch),
            reason,
        )
    };
    let sender = crate::views::chat::verified_chat_sender_domain_for_realm(
        ctx.realm_id,
        event_value,
        Some(ctx.state_store),
        Some((authority, authority.principal_id.as_str(), &device_id)),
    )
    .or_else(|| {
        let verdict = crate::views::chat::verify_chat_envelope_proof_for_realm(
            ctx.realm_id,
            event_value,
            Some(ctx.state_store),
            Some((authority, authority.principal_id.as_str(), &device_id)),
        );
        warn_pending(&format!("Strand sender proof is {verdict:?}"));
        None
    })?;
    let plaintext =
        crate::state::projection::try_local_mls_decrypt_core_for_scope_from_verified_sender(
            ctx.state_store,
            ctx.realm_id,
            authority,
            &device_id,
            value,
            &event.scope_ref,
            event.kind.as_str(),
            &sender,
            None,
        )
        .or_else(|| {
            warn_pending("Strand verified envelope or receive state is unavailable");
            None
        })?;
    let plaintext: Value = serde_json::from_slice(&plaintext).ok()?;
    Some(strand_body_display_text(Some(&plaintext)))
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

/// Resolve a projected private Strand field without its signed Event context.
///
/// 1. **Local plaintext sidecar** (`save_private_plaintext`) — stored as the JSON-serialized
///    patch value, parsed through `strand_body_display_text` to keep write/read symmetric.
///    Event overlays independently try verified decryption, including for the same Account.
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
